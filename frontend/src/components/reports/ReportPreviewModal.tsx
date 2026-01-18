import React, { useState, useEffect } from 'react';
import { X, Download, FileText, Code, Loader2, ExternalLink } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { reportAPI } from '../../services/api';

interface Report {
  id: string;
  name: string;
  format: string;
  status: string;
  template_id: string;
  scan_id: string;
  created_at: string;
}

interface ReportPreviewModalProps {
  report: Report;
  onClose: () => void;
  onDownload: (reportId: string) => void;
}

type TabType = 'preview' | 'json';

export default function ReportPreviewModal({
  report,
  onClose,
  onDownload,
}: ReportPreviewModalProps) {
  const [activeTab, setActiveTab] = useState<TabType>('preview');

  // Fetch preview HTML
  const { data: previewHtml, isLoading: isLoadingPreview, error: previewError } = useQuery({
    queryKey: ['reportPreview', report.id],
    queryFn: async () => {
      const response = await fetch(`/api/reports/${report.id}/preview`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      if (!response.ok) {
        throw new Error('Failed to load preview');
      }
      return response.text();
    },
    enabled: activeTab === 'preview',
  });

  // Fetch report JSON data
  const { data: reportData, isLoading: isLoadingJson, error: jsonError } = useQuery({
    queryKey: ['reportJson', report.id],
    queryFn: async () => {
      const response = await reportAPI.getById(report.id);
      return response.data;
    },
    enabled: activeTab === 'json',
  });

  // Close on escape key
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [onClose]);

  // Prevent body scroll when modal is open
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = '';
    };
  }, []);

  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm"
      onClick={handleBackdropClick}
    >
      <div className="relative w-full h-full max-w-6xl max-h-[90vh] m-4 bg-slate-800 rounded-lg shadow-2xl flex flex-col overflow-hidden border border-slate-600">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-600">
          <div className="flex items-center gap-4">
            <FileText className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-lg font-semibold text-white">{report.name}</h2>
              <p className="text-sm text-slate-400">
                {report.format.toUpperCase()} &bull; {report.template_id}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onDownload(report.id)}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors"
            >
              <Download className="w-4 h-4" />
              Download
            </button>
            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-slate-600">
          <button
            onClick={() => setActiveTab('preview')}
            className={`flex items-center gap-2 px-6 py-3 text-sm font-medium transition-colors ${
              activeTab === 'preview'
                ? 'text-cyan-400 border-b-2 border-cyan-400 bg-slate-700/50'
                : 'text-slate-400 hover:text-white hover:bg-slate-700/30'
            }`}
          >
            <ExternalLink className="w-4 h-4" />
            Preview
          </button>
          <button
            onClick={() => setActiveTab('json')}
            className={`flex items-center gap-2 px-6 py-3 text-sm font-medium transition-colors ${
              activeTab === 'json'
                ? 'text-cyan-400 border-b-2 border-cyan-400 bg-slate-700/50'
                : 'text-slate-400 hover:text-white hover:bg-slate-700/30'
            }`}
          >
            <Code className="w-4 h-4" />
            JSON Data
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto">
          {activeTab === 'preview' && (
            <div className="h-full">
              {isLoadingPreview && (
                <div className="flex items-center justify-center h-full">
                  <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
                </div>
              )}
              {previewError && (
                <div className="flex items-center justify-center h-full text-red-400">
                  <p>Failed to load preview. Please try downloading the report directly.</p>
                </div>
              )}
              {previewHtml && (
                <iframe
                  srcDoc={previewHtml}
                  title="Report Preview"
                  className="w-full h-full border-0"
                  sandbox="allow-same-origin"
                />
              )}
            </div>
          )}

          {activeTab === 'json' && (
            <div className="p-4 h-full">
              {isLoadingJson && (
                <div className="flex items-center justify-center h-full">
                  <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
                </div>
              )}
              {jsonError && (
                <div className="flex items-center justify-center h-full text-red-400">
                  <p>Failed to load report data.</p>
                </div>
              )}
              {reportData && (
                <pre className="bg-slate-900 rounded-lg p-4 overflow-auto h-full text-sm text-slate-300 font-mono">
                  {JSON.stringify(reportData, null, 2)}
                </pre>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
