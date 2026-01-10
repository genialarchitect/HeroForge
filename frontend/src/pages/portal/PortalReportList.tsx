import { useState, useEffect } from 'react';
import { PortalLayout } from '../../components/portal/PortalLayout';
import { portalReportsAPI } from '../../services/portalApi';
import type { PortalReport } from '../../types';
import { FileText, Download, Loader2 } from 'lucide-react';

export default function PortalReportList() {
  const [reports, setReports] = useState<PortalReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [downloading, setDownloading] = useState<string | null>(null);

  useEffect(() => {
    loadReports();
  }, []);

  const loadReports = async () => {
    try {
      const response = await portalReportsAPI.getAll();
      setReports(response.data);
    } catch (err) {
      setError('Failed to load reports');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (report: PortalReport) => {
    setDownloading(report.id);
    try {
      const response = await portalReportsAPI.download(report.id);
      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = report.name.replace(/\s+/g, '_') + '.' + (report.format || 'pdf');
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Failed to download report:', err);
      alert('Failed to download report');
    } finally {
      setDownloading(null);
    }
  };

  if (loading) {
    return (
      <PortalLayout>
        <div className="flex items-center justify-center h-64">
          <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      </PortalLayout>
    );
  }

  return (
    <PortalLayout>
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Reports</h1>

        {error && (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 p-4 rounded-lg">{error}</div>
        )}

        {reports.length === 0 ? (
          <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-8 text-center">
            <FileText className="mx-auto h-12 w-12 text-slate-400 dark:text-slate-500 mb-4" />
            <p className="text-slate-500 dark:text-slate-400">No reports available</p>
            <p className="text-sm text-slate-400 dark:text-slate-500 mt-1">Reports will appear here once they are generated</p>
          </div>
        ) : (
          <div className="grid gap-4">
            {reports.map(report => (
              <div
                key={report.id}
                className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6 flex items-center justify-between"
              >
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center">
                    <FileText className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  </div>
                  <div>
                    <h3 className="text-lg font-medium text-slate-900 dark:text-white">{report.name}</h3>
                    <div className="flex items-center gap-3 text-sm text-slate-500 dark:text-slate-400 mt-1">
                      <span className="uppercase">{report.format || 'PDF'}</span>
                      <span>{new Date(report.created_at).toLocaleDateString()}</span>
                      {report.engagement_name && (
                        <span className="text-slate-400 dark:text-slate-500">{report.engagement_name}</span>
                      )}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => handleDownload(report)}
                  disabled={downloading === report.id}
                  className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary-dark text-white rounded-lg disabled:opacity-50 transition-colors"
                >
                  {downloading === report.id ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Downloading...
                    </>
                  ) : (
                    <>
                      <Download className="w-4 h-4" />
                      Download
                    </>
                  )}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </PortalLayout>
  );
}
