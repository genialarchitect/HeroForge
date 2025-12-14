import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import {
  FileText,
  Download,
  Trash2,
  RefreshCw,
  Clock,
  CheckCircle,
  XCircle,
  Loader,
} from 'lucide-react';
import { reportAPI } from '../../services/api';
import type { Report } from '../../types';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import { format } from 'date-fns';

interface ReportListProps {
  scanId?: string;
  onGenerateNew?: () => void;
}

const ReportList: React.FC<ReportListProps> = ({ scanId, onGenerateNew }) => {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  useEffect(() => {
    loadReports();
    // Poll for status updates
    const interval = setInterval(() => {
      const pendingReports = reports.filter(
        (r) => r.status === 'pending' || r.status === 'generating'
      );
      if (pendingReports.length > 0) {
        loadReports();
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [scanId]);

  const loadReports = async () => {
    try {
      const response = await reportAPI.getAll(scanId);
      setReports(response.data);
    } catch (error) {
      toast.error('Failed to load reports');
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (report: Report) => {
    if (report.status !== 'completed') {
      toast.warning('Report is not ready for download');
      return;
    }

    setDownloading(report.id);
    try {
      const response = await reportAPI.download(report.id);
      const blob = new Blob([response.data], { type: response.headers['content-type'] });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.name.replace(/\s+/g, '_')}.${report.format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast.success('Report downloaded');
    } catch (error) {
      toast.error('Failed to download report');
    } finally {
      setDownloading(null);
    }
  };

  const handleDelete = async (report: Report) => {
    if (!confirm(`Delete report "${report.name}"?`)) {
      return;
    }

    setDeleting(report.id);
    try {
      await reportAPI.delete(report.id);
      setReports((prev) => prev.filter((r) => r.id !== report.id));
      toast.success('Report deleted');
    } catch (error) {
      toast.error('Failed to delete report');
    } finally {
      setDeleting(null);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />;
      case 'generating':
        return <Loader className="h-4 w-4 text-blue-500 animate-spin" />;
      default:
        return <Clock className="h-4 w-4 text-slate-400" />;
    }
  };

  const getStatusBadgeType = (status: string): 'completed' | 'running' | 'failed' | 'pending' => {
    switch (status) {
      case 'completed':
        return 'completed';
      case 'generating':
        return 'running';
      case 'failed':
        return 'failed';
      default:
        return 'pending';
    }
  };

  const formatFileSize = (bytes?: number) => {
    if (!bytes) return '-';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  if (loading) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Card>
    );
  }

  if (reports.length === 0) {
    return (
      <Card>
        <div className="text-center py-12">
          <FileText className="h-12 w-12 mx-auto mb-4 text-slate-500" />
          <h3 className="text-lg font-medium text-white mb-2">No Reports Yet</h3>
          <p className="text-slate-400 mb-4">
            Generate a professional report from your scan results.
          </p>
          {onGenerateNew && (
            <Button onClick={onGenerateNew}>
              <FileText className="h-4 w-4 mr-2" />
              Generate Report
            </Button>
          )}
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
          <FileText className="h-5 w-5 text-primary" />
          Reports
        </h3>
        <div className="flex items-center gap-2">
          <button
            onClick={loadReports}
            className="p-2 hover:bg-dark-surface rounded-lg transition-colors"
            title="Refresh"
          >
            <RefreshCw className="h-4 w-4 text-slate-400" />
          </button>
          {onGenerateNew && (
            <Button size="sm" onClick={onGenerateNew}>
              <FileText className="h-4 w-4 mr-1" />
              New Report
            </Button>
          )}
        </div>
      </div>

      <div className="space-y-3">
        {reports.map((report) => (
          <div
            key={report.id}
            className="flex items-center justify-between p-4 bg-dark-surface rounded-lg border border-dark-border hover:border-primary/30 transition-colors"
          >
            <div className="flex items-center gap-4">
              <div className="p-2 bg-dark-bg rounded-lg">
                {getStatusIcon(report.status)}
              </div>
              <div>
                <p className="font-medium text-white">{report.name}</p>
                <div className="flex items-center gap-3 text-sm text-slate-400 mt-1">
                  <span className="uppercase font-mono">{report.format}</span>
                  <span>|</span>
                  <span>{report.template_id}</span>
                  <span>|</span>
                  <span>{format(new Date(report.created_at), 'MMM d, yyyy HH:mm')}</span>
                  {report.file_size && (
                    <>
                      <span>|</span>
                      <span>{formatFileSize(report.file_size)}</span>
                    </>
                  )}
                </div>
                {report.error_message && (
                  <p className="text-sm text-red-400 mt-1">{report.error_message}</p>
                )}
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Badge variant="status" type={getStatusBadgeType(report.status)}>
                {report.status}
              </Badge>

              <div className="flex items-center gap-1">
                <button
                  onClick={() => handleDownload(report)}
                  disabled={report.status !== 'completed' || downloading === report.id}
                  className={`p-2 rounded-lg transition-colors ${
                    report.status === 'completed'
                      ? 'hover:bg-dark-bg text-slate-400 hover:text-white'
                      : 'text-slate-600 cursor-not-allowed'
                  }`}
                  title="Download"
                >
                  {downloading === report.id ? (
                    <Loader className="h-4 w-4 animate-spin" />
                  ) : (
                    <Download className="h-4 w-4" />
                  )}
                </button>
                <button
                  onClick={() => handleDelete(report)}
                  disabled={deleting === report.id}
                  className="p-2 rounded-lg text-slate-400 hover:text-red-400 hover:bg-dark-bg transition-colors"
                  title="Delete"
                >
                  {deleting === report.id ? (
                    <Loader className="h-4 w-4 animate-spin" />
                  ) : (
                    <Trash2 className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
};

export default ReportList;
