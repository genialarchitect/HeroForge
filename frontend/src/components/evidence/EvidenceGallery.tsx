import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Camera,
  X,
  ChevronLeft,
  ChevronRight,
  Download,
  ExternalLink,
  Loader2,
  Image,
  FileCode,
  Terminal,
  Globe,
} from 'lucide-react';

interface ScanEvidence {
  id: string;
  scan_id: string;
  finding_id: string | null;
  evidence_type: string;
  description: string | null;
  file_path: string;
  file_size: number | null;
  width: number | null;
  height: number | null;
  step_number: number | null;
  selector: string | null;
  url: string | null;
  captured_at: string;
}

interface EvidenceGalleryProps {
  scanId?: string;
  findingId?: string;
  title?: string;
}

const EVIDENCE_TYPE_ICONS: Record<string, React.ReactNode> = {
  screenshot: <Camera className="w-4 h-4" />,
  terminal_output: <Terminal className="w-4 h-4" />,
  request_response: <Globe className="w-4 h-4" />,
  file_content: <FileCode className="w-4 h-4" />,
  network_capture: <Globe className="w-4 h-4" />,
};

const EVIDENCE_TYPE_LABELS: Record<string, string> = {
  screenshot: 'Screenshot',
  terminal_output: 'Terminal Output',
  request_response: 'Request/Response',
  file_content: 'File Content',
  network_capture: 'Network Capture',
};

export default function EvidenceGallery({
  scanId,
  findingId,
  title = 'Evidence',
}: EvidenceGalleryProps) {
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);

  // Fetch evidence
  const { data: evidence, isLoading, error } = useQuery<ScanEvidence[]>({
    queryKey: ['evidence', scanId, findingId],
    queryFn: async () => {
      const token = localStorage.getItem('token');
      let url = '';
      if (findingId && scanId) {
        url = `/api/scans/${scanId}/findings/${findingId}/evidence`;
      } else if (scanId) {
        url = `/api/scans/${scanId}/evidence`;
      } else {
        return [];
      }

      const response = await fetch(url, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch evidence');
      }

      return response.json();
    },
    enabled: !!scanId,
  });

  const handlePrevious = () => {
    if (selectedIndex !== null && selectedIndex > 0) {
      setSelectedIndex(selectedIndex - 1);
    }
  };

  const handleNext = () => {
    if (selectedIndex !== null && evidence && selectedIndex < evidence.length - 1) {
      setSelectedIndex(selectedIndex + 1);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowLeft') {
      handlePrevious();
    } else if (e.key === 'ArrowRight') {
      handleNext();
    } else if (e.key === 'Escape') {
      setSelectedIndex(null);
    }
  };

  const getEvidenceImageUrl = (item: ScanEvidence) => {
    // In production, this would return a URL to the actual screenshot
    // For now, return a placeholder based on the file path
    return `/api/files/${encodeURIComponent(item.file_path)}`;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 text-red-400 text-sm">
        Failed to load evidence
      </div>
    );
  }

  if (!evidence || evidence.length === 0) {
    return (
      <div className="p-4 text-slate-400 text-sm text-center">
        <Image className="w-8 h-8 mx-auto mb-2 text-slate-600" />
        <p>No evidence captured for this {findingId ? 'finding' : 'scan'}</p>
      </div>
    );
  }

  // Group evidence by step number for multi-step sequences
  const hasSteps = evidence.some((e) => e.step_number !== null);

  return (
    <div className="space-y-4">
      {title && (
        <h3 className="text-sm font-medium text-white flex items-center gap-2">
          <Camera className="w-4 h-4 text-cyan-400" />
          {title} ({evidence.length})
        </h3>
      )}

      {/* Thumbnail Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
        {evidence.map((item, index) => (
          <button
            key={item.id}
            onClick={() => setSelectedIndex(index)}
            className="relative aspect-video bg-slate-800 rounded-lg overflow-hidden border border-slate-600 hover:border-cyan-500 transition-colors group"
          >
            {/* Thumbnail Preview */}
            <div className="absolute inset-0 flex items-center justify-center bg-slate-700">
              {item.evidence_type === 'screenshot' ? (
                <Camera className="w-6 h-6 text-slate-500" />
              ) : (
                EVIDENCE_TYPE_ICONS[item.evidence_type] || (
                  <FileCode className="w-6 h-6 text-slate-500" />
                )
              )}
            </div>

            {/* Step Number Badge */}
            {item.step_number !== null && (
              <div className="absolute top-2 left-2 bg-cyan-500 text-white text-xs font-bold px-2 py-0.5 rounded">
                Step {item.step_number}
              </div>
            )}

            {/* Type Badge */}
            <div className="absolute bottom-2 left-2 bg-slate-900/80 text-slate-300 text-xs px-2 py-0.5 rounded flex items-center gap-1">
              {EVIDENCE_TYPE_ICONS[item.evidence_type]}
              {EVIDENCE_TYPE_LABELS[item.evidence_type] || item.evidence_type}
            </div>

            {/* Hover Overlay */}
            <div className="absolute inset-0 bg-cyan-500/10 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
              <ExternalLink className="w-6 h-6 text-cyan-400" />
            </div>
          </button>
        ))}
      </div>

      {/* Lightbox Modal */}
      {selectedIndex !== null && evidence[selectedIndex] && (
        <div
          className="fixed inset-0 z-50 bg-black/90 flex items-center justify-center"
          onClick={() => setSelectedIndex(null)}
          onKeyDown={handleKeyDown}
          tabIndex={0}
        >
          <div
            className="relative max-w-6xl max-h-[90vh] mx-4"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Close Button */}
            <button
              onClick={() => setSelectedIndex(null)}
              className="absolute -top-10 right-0 p-2 text-white/60 hover:text-white transition-colors"
            >
              <X className="w-6 h-6" />
            </button>

            {/* Navigation */}
            {selectedIndex > 0 && (
              <button
                onClick={handlePrevious}
                className="absolute left-0 top-1/2 -translate-y-1/2 -ml-12 p-2 text-white/60 hover:text-white transition-colors"
              >
                <ChevronLeft className="w-8 h-8" />
              </button>
            )}
            {selectedIndex < evidence.length - 1 && (
              <button
                onClick={handleNext}
                className="absolute right-0 top-1/2 -translate-y-1/2 -mr-12 p-2 text-white/60 hover:text-white transition-colors"
              >
                <ChevronRight className="w-8 h-8" />
              </button>
            )}

            {/* Main Content */}
            <div className="bg-slate-800 rounded-lg overflow-hidden">
              {/* Image/Content Area */}
              <div className="relative bg-slate-900 flex items-center justify-center min-h-[400px]">
                {evidence[selectedIndex].evidence_type === 'screenshot' ? (
                  <div className="text-center p-8">
                    <Camera className="w-16 h-16 text-slate-600 mx-auto mb-4" />
                    <p className="text-slate-400">Screenshot captured</p>
                    <p className="text-slate-500 text-sm mt-1">
                      {evidence[selectedIndex].file_path}
                    </p>
                  </div>
                ) : (
                  <div className="text-center p-8">
                    {EVIDENCE_TYPE_ICONS[evidence[selectedIndex].evidence_type]}
                    <p className="text-slate-400 mt-4">
                      {EVIDENCE_TYPE_LABELS[evidence[selectedIndex].evidence_type]}
                    </p>
                  </div>
                )}
              </div>

              {/* Details Panel */}
              <div className="p-4 border-t border-slate-700">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    {evidence[selectedIndex].step_number !== null && (
                      <span className="inline-block bg-cyan-500/20 text-cyan-400 text-xs font-medium px-2 py-0.5 rounded mb-2">
                        Step {evidence[selectedIndex].step_number}
                      </span>
                    )}
                    {evidence[selectedIndex].description && (
                      <p className="text-white font-medium">
                        {evidence[selectedIndex].description}
                      </p>
                    )}
                    {evidence[selectedIndex].url && (
                      <p className="text-slate-400 text-sm truncate mt-1">
                        {evidence[selectedIndex].url}
                      </p>
                    )}
                    {evidence[selectedIndex].selector && (
                      <p className="text-slate-500 text-xs mt-1 font-mono">
                        Selector: {evidence[selectedIndex].selector}
                      </p>
                    )}
                    <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                      {evidence[selectedIndex].width && evidence[selectedIndex].height && (
                        <span>
                          {evidence[selectedIndex].width} x {evidence[selectedIndex].height}
                        </span>
                      )}
                      {evidence[selectedIndex].file_size && (
                        <span>
                          {(evidence[selectedIndex].file_size / 1024).toFixed(1)} KB
                        </span>
                      )}
                      <span>
                        {new Date(evidence[selectedIndex].captured_at).toLocaleString()}
                      </span>
                    </div>
                  </div>
                  <button
                    className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded text-sm text-white transition-colors"
                    onClick={() => {
                      // Download the evidence file
                      window.open(getEvidenceImageUrl(evidence[selectedIndex]), '_blank');
                    }}
                  >
                    <Download className="w-4 h-4" />
                    Download
                  </button>
                </div>

                {/* Step Navigation for Multi-Step Sequences */}
                {hasSteps && (
                  <div className="flex items-center justify-center gap-2 mt-4 pt-4 border-t border-slate-700">
                    {evidence.map((item, index) => (
                      <button
                        key={item.id}
                        onClick={() => setSelectedIndex(index)}
                        className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium transition-colors ${
                          index === selectedIndex
                            ? 'bg-cyan-500 text-white'
                            : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
                        }`}
                      >
                        {item.step_number || index + 1}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Counter */}
            <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 text-white/60 text-sm">
              {selectedIndex + 1} / {evidence.length}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Inline evidence preview for use in finding cards
 */
export function EvidencePreviewInline({
  scanId,
  findingId,
}: {
  scanId: string;
  findingId: string;
}) {
  const { data: evidence } = useQuery<ScanEvidence[]>({
    queryKey: ['evidence', scanId, findingId],
    queryFn: async () => {
      const token = localStorage.getItem('token');
      const response = await fetch(
        `/api/scans/${scanId}/findings/${findingId}/evidence`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        return [];
      }

      return response.json();
    },
  });

  if (!evidence || evidence.length === 0) {
    return null;
  }

  return (
    <div className="flex items-center gap-1 text-xs text-slate-400">
      <Camera className="w-3 h-3" />
      <span>{evidence.length} evidence</span>
    </div>
  );
}
