import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  FileText,
  Download,
  Trash2,
  RefreshCw,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Plus,
  Calendar,
  FileJson,
  FileType,
  File,
  Eye,
  StickyNote,
  X,
  Save,
} from 'lucide-react';
import { toast } from 'react-toastify';
import Button from '../components/ui/Button';
import { Layout } from '../components/layout/Layout';
import UnifiedReportCreator from '../components/reports/UnifiedReportCreator';
import ReportPreviewModal from '../components/reports/ReportPreviewModal';
import ScheduledReports from '../components/settings/ScheduledReports';
import { reportAPI } from '../services/api';
import type {
  Report,
  ReportNotesResponse,
} from '../types';

type TabType = 'reports' | 'scheduled' | 'create';

const getStatusIcon = (status: string) => {
  switch (status.toLowerCase()) {
    case 'completed':
      return <CheckCircle className="w-4 h-4 text-green-400" />;
    case 'failed':
      return <XCircle className="w-4 h-4 text-red-400" />;
    case 'generating':
      return <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />;
    default:
      return <Clock className="w-4 h-4 text-yellow-400" />;
  }
};

const getFormatIcon = (format: string) => {
  switch (format.toLowerCase()) {
    case 'pdf':
      return <File className="w-4 h-4 text-red-400" />;
    case 'html':
      return <FileType className="w-4 h-4 text-orange-400" />;
    case 'json':
      return <FileJson className="w-4 h-4 text-blue-400" />;
    default:
      return <FileText className="w-4 h-4 text-slate-400" />;
  }
};

const formatFileSize = (bytes: number | null | undefined) => {
  if (!bytes) return '-';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

// Operator Notes Panel Component
function NotesPanel({
  report,
  onClose,
}: {
  report: Report;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [notes, setNotes] = useState(report.operator_notes || '');
  const [hasChanges, setHasChanges] = useState(false);

  // Fetch notes for this report
  const { data: notesData, isLoading } = useQuery<ReportNotesResponse>({
    queryKey: ['report-notes', report.id],
    queryFn: async () => {
      const response = await reportAPI.getNotes(report.id);
      return response.data;
    },
  });

  // Update notes state when data is fetched
  useEffect(() => {
    if (notesData) {
      setNotes(notesData.operator_notes || '');
    }
  }, [notesData]);

  // Update notes mutation
  const updateMutation = useMutation({
    mutationFn: () => reportAPI.updateNotes(report.id, { operator_notes: notes }),
    onSuccess: () => {
      toast.success('Notes saved');
      setHasChanges(false);
      queryClient.invalidateQueries({ queryKey: ['report-notes', report.id] });
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
    onError: () => toast.error('Failed to save notes'),
  });

  const handleSave = () => {
    updateMutation.mutate();
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Panel */}
      <div className="absolute right-0 top-0 h-full w-full max-w-lg bg-slate-800 border-l border-slate-700 shadow-xl">
        <div className="flex flex-col h-full">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-slate-700">
            <div className="flex items-center gap-2">
              <StickyNote className="w-5 h-5 text-cyan-400" />
              <h3 className="text-lg font-semibold text-white">Operator Notes</h3>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
            >
              <X className="w-5 h-5 text-slate-400" />
            </button>
          </div>

          {/* Report Info */}
          <div className="p-4 border-b border-slate-700 bg-slate-900/50">
            <p className="text-sm text-slate-400">Report</p>
            <p className="text-white font-medium">{report.name}</p>
            <p className="text-xs text-slate-500 mt-1">
              {new Date(report.created_at).toLocaleString()}
            </p>
          </div>

          {/* Notes Content */}
          <div className="flex-1 p-4 overflow-y-auto">
            {isLoading ? (
              <div className="flex items-center justify-center h-32">
                <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin" />
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Assessment Notes
                  </label>
                  <p className="text-xs text-slate-500 mb-2">
                    Add notes about the assessment, methodology, or observations. These notes will be included in regenerated reports.
                  </p>
                  <textarea
                    value={notes}
                    onChange={(e) => {
                      setNotes(e.target.value);
                      setHasChanges(true);
                    }}
                    placeholder="Enter operator notes for this report..."
                    className="w-full h-64 bg-slate-900 border border-slate-600 rounded-lg px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 resize-none"
                  />
                </div>

                {notesData?.finding_notes && notesData.finding_notes.length > 0 && (
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Finding-Specific Notes ({notesData.finding_notes.length})
                    </label>
                    <div className="space-y-2">
                      {notesData.finding_notes.map((note) => (
                        <div
                          key={note.id}
                          className="p-3 bg-slate-900 rounded-lg border border-slate-700"
                        >
                          <p className="text-xs text-slate-500 mb-1">
                            Finding: {note.finding_id}
                          </p>
                          <p className="text-sm text-slate-300">{note.notes}</p>
                          <p className="text-xs text-slate-600 mt-1">
                            {new Date(note.created_at).toLocaleString()}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {notesData?.operator_notes_updated_at && (
                  <p className="text-xs text-slate-500">
                    Last updated: {new Date(notesData.operator_notes_updated_at).toLocaleString()}
                  </p>
                )}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-4 border-t border-slate-700 bg-slate-900/50">
            <div className="flex items-center justify-between">
              <p className="text-xs text-slate-500">
                {hasChanges ? 'Unsaved changes' : 'No changes'}
              </p>
              <div className="flex items-center gap-2">
                <Button variant="secondary" onClick={onClose}>
                  Cancel
                </Button>
                <Button
                  onClick={handleSave}
                  disabled={!hasChanges || updateMutation.isPending}
                >
                  {updateMutation.isPending ? (
                    <RefreshCw className="w-4 h-4 animate-spin mr-2" />
                  ) : (
                    <Save className="w-4 h-4 mr-2" />
                  )}
                  Save Notes
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// CreateReportForm has been replaced by UnifiedReportCreator

// ScheduledReportsSection has been replaced by importing the full ScheduledReports component

// Main Page Component
export default function ReportsPage() {
  const [activeTab, setActiveTab] = useState<TabType>('reports');
  const [notesReport, setNotesReport] = useState<Report | null>(null);
  const [previewReport, setPreviewReport] = useState<Report | null>(null);
  const queryClient = useQueryClient();

  // Fetch reports
  const {
    data: reports,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ['reports'],
    queryFn: async () => {
      const response = await reportAPI.getAll();
      return response.data;
    },
    refetchInterval: (query) => {
      // Refetch if any report is generating
      const data = query.state.data;
      const hasGenerating = data?.some((r: Report) => r.status === 'generating');
      return hasGenerating ? 5000 : false;
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => reportAPI.delete(id),
    onSuccess: () => {
      toast.success('Report deleted');
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
    onError: () => toast.error('Failed to delete report'),
  });

  // Download handler
  const handleDownload = async (report: Report) => {
    try {
      const response = await reportAPI.download(report.id);
      const blob = response.data;
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.name}.${report.format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast.success('Report downloaded');
    } catch (err) {
      toast.error('Failed to download report');
    }
  };

  const reportList = reports || [];

  return (
    <Layout>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <FileText className="w-7 h-7 text-cyan-400" />
          Report Generator
        </h1>
        <p className="text-slate-600 dark:text-slate-400 mt-1">
          Generate professional PDF, HTML, and JSON reports from scan results
        </p>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-4 mb-6 border-b border-slate-700">
        <button
          onClick={() => setActiveTab('reports')}
          className={`pb-3 px-1 border-b-2 transition-colors ${
            activeTab === 'reports'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4" />
            <span>Reports</span>
          </div>
        </button>
        <button
          onClick={() => setActiveTab('scheduled')}
          className={`pb-3 px-1 border-b-2 transition-colors ${
            activeTab === 'scheduled'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <div className="flex items-center gap-2">
            <Calendar className="w-4 h-4" />
            <span>Scheduled</span>
          </div>
        </button>
        <button
          onClick={() => setActiveTab('create')}
          className={`pb-3 px-1 border-b-2 transition-colors ${
            activeTab === 'create'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <div className="flex items-center gap-2">
            <Plus className="w-4 h-4" />
            <span>Create</span>
          </div>
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === 'reports' && (
        <div className="bg-slate-800 rounded-lg border border-slate-700">
          <div className="p-4 border-b border-slate-700 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Generated Reports</h3>
            <Button variant="secondary" size="sm" onClick={() => refetch()}>
              <RefreshCw className="w-4 h-4" />
            </Button>
          </div>

          <div className="divide-y divide-slate-700">
            {isLoading ? (
              <div className="p-8 text-center">
                <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
              </div>
            ) : reportList.length === 0 ? (
              <div className="p-8 text-center text-slate-400">
                <FileText className="w-12 h-12 mx-auto mb-3 text-slate-600" />
                <p>No reports generated yet</p>
                <Button
                  variant="secondary"
                  className="mt-4"
                  onClick={() => setActiveTab('create')}
                >
                  <Plus className="w-4 h-4 mr-2" />
                  Create Your First Report
                </Button>
              </div>
            ) : (
              reportList.map((report: Report) => (
                <div
                  key={report.id}
                  className="p-4 hover:bg-slate-700/50 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(report.status)}
                        {getFormatIcon(report.format)}
                        <span className="text-white font-medium">{report.name}</span>
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-sm text-slate-400">
                        <span>{new Date(report.created_at).toLocaleString()}</span>
                        <span>|</span>
                        <span className="capitalize">{report.template_id}</span>
                        {report.file_size && (
                          <>
                            <span>|</span>
                            <span>{formatFileSize(report.file_size)}</span>
                          </>
                        )}
                      </div>
                      {report.error_message && (
                        <div className="flex items-center gap-1 mt-1 text-sm text-red-400">
                          <AlertTriangle className="w-3 h-3" />
                          {report.error_message}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setNotesReport(report)}
                        className="p-2 hover:bg-slate-600 rounded-lg transition-colors"
                        title="Operator Notes"
                      >
                        <StickyNote className={`w-4 h-4 ${report.operator_notes ? 'text-yellow-400' : 'text-slate-400'}`} />
                      </button>
                      {report.status === 'completed' && (
                        <>
                          <button
                            onClick={() => setPreviewReport(report)}
                            className="p-2 hover:bg-slate-600 rounded-lg transition-colors"
                            title="Preview"
                          >
                            <Eye className="w-4 h-4 text-slate-400 hover:text-cyan-400" />
                          </button>
                          <button
                            onClick={() => handleDownload(report)}
                            className="p-2 hover:bg-slate-600 rounded-lg transition-colors"
                            title="Download"
                          >
                            <Download className="w-4 h-4 text-cyan-400" />
                          </button>
                        </>
                      )}
                      <button
                        onClick={() => {
                          if (confirm('Delete this report?')) {
                            deleteMutation.mutate(report.id);
                          }
                        }}
                        className="p-2 hover:bg-slate-600 rounded-lg transition-colors"
                      >
                        <Trash2 className="w-4 h-4 text-slate-400 hover:text-red-400" />
                      </button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {activeTab === 'scheduled' && <ScheduledReports />}

      {activeTab === 'create' && (
        <div className="max-w-3xl">
          <UnifiedReportCreator
            onReportCreated={() => {
              setActiveTab('reports');
              queryClient.invalidateQueries({ queryKey: ['reports'] });
            }}
          />
        </div>
      )}

      {/* Notes Panel */}
      {notesReport && (
        <NotesPanel
          report={notesReport}
          onClose={() => setNotesReport(null)}
        />
      )}

      {/* Preview Modal */}
      {previewReport && (
        <ReportPreviewModal
          report={previewReport}
          onClose={() => setPreviewReport(null)}
          onDownload={(reportId) => {
            const report = reports?.find((r) => r.id === reportId);
            if (report) {
              handleDownload(report);
            }
            setPreviewReport(null);
          }}
        />
      )}
    </Layout>
  );
}
