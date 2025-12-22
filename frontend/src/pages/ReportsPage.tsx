import React, { useState } from 'react';
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
  Settings,
  FileJson,
  FileType,
  File,
  ChevronRight,
  Play,
  Pause,
  Eye,
} from 'lucide-react';
import { toast } from 'react-toastify';
import Button from '../components/ui/Button';
import { Layout } from '../components/layout/Layout';
import { reportAPI, scanAPI, scheduledReportAPI, ScheduledReport } from '../services/api';
import type {
  Report,
  ReportTemplate,
  ReportFormat,
  ReportTemplateId,
  ScanResult,
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

// Create Report Form Component
function CreateReportForm({ onReportCreated }: { onReportCreated: () => void }) {
  const [selectedScan, setSelectedScan] = useState<string>('');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [format, setFormat] = useState<ReportFormat>('pdf');
  const [templateId, setTemplateId] = useState<ReportTemplateId>('technical');
  const [sections, setSections] = useState<string[]>([]);
  const [includeBranding, setIncludeBranding] = useState(true);
  const [companyName, setCompanyName] = useState('');

  // Fetch scans
  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ['scans-for-report'],
    queryFn: async () => {
      const response = await scanAPI.getAll();
      return response.data;
    },
  });

  // Fetch templates
  const { data: templates } = useQuery({
    queryKey: ['report-templates'],
    queryFn: async () => {
      const response = await reportAPI.getTemplates();
      return response.data;
    },
  });

  const createMutation = useMutation({
    mutationFn: (data: { scan_id: string; name: string; description?: string; format: ReportFormat; template_id: ReportTemplateId; sections: string[]; options?: { include_branding?: boolean; company_name?: string } }) => reportAPI.create(data),
    onSuccess: () => {
      toast.success('Report generation started');
      onReportCreated();
      setName('');
      setDescription('');
      setSelectedScan('');
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Failed to create report');
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedScan) {
      toast.error('Please select a scan');
      return;
    }

    createMutation.mutate({
      scan_id: selectedScan,
      name: name || `Report - ${new Date().toLocaleDateString()}`,
      description: description || undefined,
      format,
      template_id: templateId,
      sections,
      options: {
        include_branding: includeBranding,
        company_name: companyName || undefined,
      },
    });
  };

  const scans = scansData || [];
  const completedScans = scans.filter((s: ScanResult) => s.status === 'completed');

  const allSections = [
    { id: 'toc', label: 'Table of Contents' },
    { id: 'executive', label: 'Executive Summary' },
    { id: 'risk', label: 'Risk Overview' },
    { id: 'hosts', label: 'Host Inventory' },
    { id: 'ports', label: 'Port Analysis' },
    { id: 'vulns', label: 'Vulnerability Findings' },
    { id: 'enumeration', label: 'Service Enumeration' },
    { id: 'remediation', label: 'Remediation Recommendations' },
    { id: 'appendix', label: 'Appendix' },
  ];

  return (
    <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
      <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <Plus className="w-5 h-5 text-cyan-400" />
        Generate Report
      </h3>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Scan Selection */}
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Select Scan *
          </label>
          <select
            value={selectedScan}
            onChange={(e) => setSelectedScan(e.target.value)}
            className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            required
          >
            <option value="">Choose a completed scan...</option>
            {completedScans.map((scan: ScanResult) => (
              <option key={scan.id} value={scan.id}>
                {scan.name} ({new Date(scan.created_at).toLocaleDateString()})
              </option>
            ))}
          </select>
          {scansLoading && (
            <p className="text-sm text-slate-400 mt-1">Loading scans...</p>
          )}
        </div>

        {/* Report Name */}
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Report Name
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Monthly Security Assessment"
            className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        {/* Description */}
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Description
          </label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional description..."
            rows={2}
            className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        {/* Template Selection */}
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Report Template
          </label>
          <div className="grid grid-cols-3 gap-2">
            {[
              { id: 'executive', label: 'Executive', desc: 'High-level summary' },
              { id: 'technical', label: 'Technical', desc: 'Detailed findings' },
              { id: 'compliance', label: 'Compliance', desc: 'Audit-ready' },
            ].map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setTemplateId(t.id as ReportTemplateId)}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  templateId === t.id
                    ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-400'
                    : 'bg-slate-700 border-slate-600 text-slate-300 hover:border-slate-500'
                }`}
              >
                <div className="font-medium">{t.label}</div>
                <div className="text-xs text-slate-400">{t.desc}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Format Selection */}
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Output Format
          </label>
          <div className="flex gap-2">
            {(['pdf', 'html', 'json'] as ReportFormat[]).map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setFormat(f)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-colors ${
                  format === f
                    ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-400'
                    : 'bg-slate-700 border-slate-600 text-slate-300 hover:border-slate-500'
                }`}
              >
                {getFormatIcon(f)}
                <span className="uppercase">{f}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Sections */}
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Include Sections (leave empty for template defaults)
          </label>
          <div className="flex flex-wrap gap-2">
            {allSections.map((section) => (
              <button
                key={section.id}
                type="button"
                onClick={() => {
                  setSections(
                    sections.includes(section.id)
                      ? sections.filter((s) => s !== section.id)
                      : [...sections, section.id]
                  );
                }}
                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                  sections.includes(section.id)
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'bg-slate-700 text-slate-400 border border-slate-600 hover:border-slate-500'
                }`}
              >
                {section.label}
              </button>
            ))}
          </div>
        </div>

        {/* Branding Options */}
        <div className="space-y-3 pt-2 border-t border-slate-700">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={includeBranding}
              onChange={(e) => setIncludeBranding(e.target.checked)}
              className="rounded bg-slate-700 border-slate-600 text-cyan-500 focus:ring-cyan-500"
            />
            <span className="text-sm text-slate-300">Include company branding</span>
          </label>

          {includeBranding && (
            <input
              type="text"
              value={companyName}
              onChange={(e) => setCompanyName(e.target.value)}
              placeholder="Company name for branding"
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          )}
        </div>

        <Button
          type="submit"
          disabled={createMutation.isPending || !selectedScan}
          className="w-full"
        >
          {createMutation.isPending ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin mr-2" />
              Generating...
            </>
          ) : (
            <>
              <FileText className="w-4 h-4 mr-2" />
              Generate Report
            </>
          )}
        </Button>
      </form>
    </div>
  );
}

// Scheduled Reports Component
function ScheduledReportsSection() {
  const queryClient = useQueryClient();

  const { data: scheduledReports, isLoading } = useQuery({
    queryKey: ['scheduled-reports'],
    queryFn: async () => {
      const response = await scheduledReportAPI.getAll();
      return response.data;
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => scheduledReportAPI.delete(id),
    onSuccess: () => {
      toast.success('Scheduled report deleted');
      queryClient.invalidateQueries({ queryKey: ['scheduled-reports'] });
    },
    onError: () => toast.error('Failed to delete scheduled report'),
  });

  const runNowMutation = useMutation({
    mutationFn: (id: string) => scheduledReportAPI.runNow(id),
    onSuccess: () => {
      toast.success('Report generation started');
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
    onError: () => toast.error('Failed to run report'),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  const reports = scheduledReports || [];

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700">
      <div className="p-4 border-b border-slate-700 flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Scheduled Reports</h3>
        <Button variant="secondary" size="sm">
          <Plus className="w-4 h-4 mr-2" />
          New Schedule
        </Button>
      </div>

      <div className="divide-y divide-slate-700">
        {reports.length === 0 ? (
          <div className="p-8 text-center text-slate-400">
            <Calendar className="w-12 h-12 mx-auto mb-3 text-slate-600" />
            <p>No scheduled reports</p>
            <p className="text-sm mt-1">Create a schedule to automatically generate reports</p>
          </div>
        ) : (
          reports.map((report: ScheduledReport) => (
            <div
              key={report.id}
              className="p-4 hover:bg-slate-700/50 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${report.is_active ? 'bg-green-500' : 'bg-slate-500'}`} />
                    <span className="text-white font-medium">{report.name}</span>
                    <span className={`px-2 py-0.5 rounded text-xs ${
                      report.is_active
                        ? 'bg-green-500/20 text-green-400'
                        : 'bg-slate-600 text-slate-400'
                    }`}>
                      {report.is_active ? 'Active' : 'Disabled'}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 mt-1 text-sm text-slate-400">
                    <span>{report.schedule}</span>
                    <span>|</span>
                    <span className="uppercase">{report.format}</span>
                    <span>|</span>
                    <span className="capitalize">{report.report_type}</span>
                  </div>
                  {report.last_run_at && (
                    <div className="text-xs text-slate-500 mt-1">
                      Last run: {new Date(report.last_run_at).toLocaleString()}
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => runNowMutation.mutate(report.id)}
                    className="p-2 hover:bg-slate-600 rounded-lg transition-colors"
                    title="Run now"
                  >
                    <Play className="w-4 h-4 text-cyan-400" />
                  </button>
                  <button
                    onClick={() => {
                      if (confirm('Delete this scheduled report?')) {
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
  );
}

// Main Page Component
export default function ReportsPage() {
  const [activeTab, setActiveTab] = useState<TabType>('reports');
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
                      {report.status === 'completed' && (
                        <button
                          onClick={() => handleDownload(report)}
                          className="p-2 hover:bg-slate-600 rounded-lg transition-colors"
                          title="Download"
                        >
                          <Download className="w-4 h-4 text-cyan-400" />
                        </button>
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

      {activeTab === 'scheduled' && <ScheduledReportsSection />}

      {activeTab === 'create' && (
        <div className="max-w-2xl">
          <CreateReportForm
            onReportCreated={() => {
              setActiveTab('reports');
              queryClient.invalidateQueries({ queryKey: ['reports'] });
            }}
          />
        </div>
      )}
    </Layout>
  );
}
