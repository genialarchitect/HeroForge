import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { scheduledReportAPI } from '../../services/api';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import ConfirmationDialog from '../ui/ConfirmationDialog';
import { FileText, Plus, Edit2, Trash2, Play, Pause, Calendar, Save, X, Mail, Clock, Send } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

interface ScheduledReport {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  report_type: string;
  format: string;
  schedule: string;
  recipients: string;
  filters: string | null;
  include_charts: boolean;
  last_run_at: string | null;
  next_run_at: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

interface SchedulePreset {
  id: string;
  label: string;
  cron: string;
  description: string;
}

interface ReportFilters {
  min_severity?: string;
  frameworks?: string[];
  days_back?: number;
  scan_ids?: string[];
  customer_id?: string;
  engagement_id?: string;
}

interface FormData {
  name: string;
  description: string;
  report_type: string;
  format: string;
  schedule: string;
  recipients: string[];
  filters: ReportFilters;
  include_charts: boolean;
}

const defaultFormData: FormData = {
  name: '',
  description: '',
  report_type: 'vulnerability',
  format: 'pdf',
  schedule: '0 8 * * *',
  recipients: [],
  filters: {
    days_back: 30,
  },
  include_charts: true,
};

const REPORT_TYPES = [
  { value: 'vulnerability', label: 'Vulnerability Report', description: 'All discovered vulnerabilities with severity and remediation' },
  { value: 'scan_summary', label: 'Scan Summary', description: 'Overview of completed scans and their results' },
  { value: 'compliance', label: 'Compliance Report', description: 'Compliance framework analysis and control mappings' },
  { value: 'executive', label: 'Executive Summary', description: 'High-level security posture overview' },
];

const FORMATS = [
  { value: 'pdf', label: 'PDF' },
  { value: 'html', label: 'HTML' },
  { value: 'csv', label: 'CSV' },
];

const SEVERITY_OPTIONS = [
  { value: '', label: 'All Severities' },
  { value: 'low', label: 'Low and above' },
  { value: 'medium', label: 'Medium and above' },
  { value: 'high', label: 'High and above' },
  { value: 'critical', label: 'Critical only' },
];

const FRAMEWORKS = [
  // Original frameworks
  { value: 'cis', label: 'CIS Benchmarks' },
  { value: 'nist_800_53', label: 'NIST 800-53' },
  { value: 'nist_csf', label: 'NIST CSF' },
  { value: 'pci_dss', label: 'PCI-DSS 4.0' },
  { value: 'hipaa', label: 'HIPAA' },
  { value: 'ferpa', label: 'FERPA' },
  { value: 'soc2', label: 'SOC 2' },
  { value: 'owasp_top10', label: 'OWASP Top 10' },
  { value: 'hitrust_csf', label: 'HITRUST CSF' },
  { value: 'iso_27001', label: 'ISO 27001:2022' },
  { value: 'gdpr', label: 'GDPR' },
  { value: 'dod_stig', label: 'DoD STIG' },
  // US Federal
  { value: 'fedramp', label: 'FedRAMP' },
  { value: 'cmmc', label: 'CMMC 2.0' },
  { value: 'fisma', label: 'FISMA' },
  { value: 'nist_800_171', label: 'NIST 800-171' },
  { value: 'nist_800_82', label: 'NIST 800-82' },
  { value: 'nist_800_61', label: 'NIST 800-61' },
  { value: 'stateramp', label: 'StateRAMP' },
  { value: 'itar', label: 'ITAR' },
  { value: 'ear', label: 'EAR' },
  { value: 'dfars', label: 'DFARS 252.204-7012' },
  { value: 'icd_503', label: 'ICD 503' },
  { value: 'cnssi_1253', label: 'CNSSI 1253' },
  { value: 'rmf', label: 'Risk Management Framework' },
  { value: 'disa_cloud_srg', label: 'DISA Cloud SRG' },
  { value: 'dod_zero_trust', label: 'DoD Zero Trust' },
  { value: 'nist_privacy', label: 'NIST Privacy Framework' },
  // Industry/Sector
  { value: 'csa_ccm', label: 'CSA CCM' },
  { value: 'nerc_cip', label: 'NERC CIP' },
  { value: 'iec_62443', label: 'IEC 62443' },
  { value: 'tsa_pipeline', label: 'TSA Pipeline Security' },
  { value: 'cisa_cpgs', label: 'CISA CPGs' },
  { value: 'eo_14028', label: 'EO 14028' },
  { value: 'sox', label: 'SOX IT Controls' },
  { value: 'glba', label: 'GLBA' },
  // International
  { value: 'cyber_essentials', label: 'Cyber Essentials (UK)' },
  { value: 'ism_australia', label: 'Australian ISM' },
  { value: 'irap', label: 'IRAP' },
  { value: 'nis2', label: 'NIS2 Directive' },
  { value: 'ens_spain', label: 'ENS (Spain)' },
  { value: 'bsi_grundschutz', label: 'BSI IT-Grundschutz' },
  { value: 'c5', label: 'C5' },
  { value: 'secnumcloud', label: 'SecNumCloud' },
  { value: 'nato_cyber', label: 'NATO Cyber Defence' },
];

const ScheduledReports: React.FC = () => {
  const [reports, setReports] = useState<ScheduledReport[]>([]);
  const [presets, setPresets] = useState<SchedulePreset[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formData, setFormData] = useState<FormData>(defaultFormData);
  const [newRecipient, setNewRecipient] = useState('');
  const [deleteConfirm, setDeleteConfirm] = useState<ScheduledReport | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [runningReportId, setRunningReportId] = useState<string | null>(null);
  const [useCustomCron, setUseCustomCron] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [reportsRes, presetsRes] = await Promise.all([
        scheduledReportAPI.getAll(),
        scheduledReportAPI.getPresets(),
      ]);
      setReports(reportsRes.data);
      setPresets(presetsRes.data);
    } catch (error) {
      toast.error('Failed to load scheduled reports');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData(defaultFormData);
    setEditingId(null);
    setShowForm(false);
    setNewRecipient('');
    setUseCustomCron(false);
  };

  const handleEdit = (report: ScheduledReport) => {
    const recipients = JSON.parse(report.recipients);
    const filters = report.filters ? JSON.parse(report.filters) : {};

    setFormData({
      name: report.name,
      description: report.description || '',
      report_type: report.report_type,
      format: report.format,
      schedule: report.schedule,
      recipients,
      filters,
      include_charts: report.include_charts,
    });

    // Check if schedule is a preset or custom
    const isPreset = presets.some(p => p.cron === report.schedule);
    setUseCustomCron(!isPreset);

    setEditingId(report.id);
    setShowForm(true);
  };

  const handleAddRecipient = () => {
    const email = newRecipient.trim().toLowerCase();
    if (!email) return;

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      toast.error('Please enter a valid email address');
      return;
    }

    if (formData.recipients.includes(email)) {
      toast.warning('Email already added');
      return;
    }

    setFormData(prev => ({
      ...prev,
      recipients: [...prev.recipients, email],
    }));
    setNewRecipient('');
  };

  const handleRemoveRecipient = (email: string) => {
    setFormData(prev => ({
      ...prev,
      recipients: prev.recipients.filter(r => r !== email),
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.name.trim()) {
      toast.error('Name is required');
      return;
    }
    if (formData.recipients.length === 0) {
      toast.error('At least one recipient is required');
      return;
    }

    try {
      if (editingId) {
        await scheduledReportAPI.update(editingId, {
          name: formData.name,
          description: formData.description || undefined,
          report_type: formData.report_type,
          format: formData.format,
          schedule: formData.schedule,
          recipients: formData.recipients,
          filters: formData.filters,
          include_charts: formData.include_charts,
        });
        toast.success('Scheduled report updated');
      } else {
        await scheduledReportAPI.create({
          name: formData.name,
          description: formData.description || undefined,
          report_type: formData.report_type,
          format: formData.format,
          schedule: formData.schedule,
          recipients: formData.recipients,
          filters: formData.filters,
          include_charts: formData.include_charts,
        });
        toast.success('Scheduled report created');
      }
      resetForm();
      loadData();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to save scheduled report');
    }
  };

  const handleToggleActive = async (report: ScheduledReport) => {
    try {
      await scheduledReportAPI.update(report.id, { is_active: !report.is_active });
      toast.success(`Scheduled report ${report.is_active ? 'paused' : 'activated'}`);
      loadData();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to update');
    }
  };

  const handleRunNow = async (report: ScheduledReport) => {
    setRunningReportId(report.id);
    try {
      await scheduledReportAPI.runNow(report.id);
      toast.success('Report generation started. You will receive it via email shortly.');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to run report');
    } finally {
      setRunningReportId(null);
    }
  };

  const handleDelete = async () => {
    if (!deleteConfirm) return;

    setIsDeleting(true);
    try {
      await scheduledReportAPI.delete(deleteConfirm.id);
      toast.success(`Scheduled report "${deleteConfirm.name}" deleted`);
      loadData();
      setDeleteConfirm(null);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to delete');
    } finally {
      setIsDeleting(false);
    }
  };

  const formatSchedule = (cron: string): string => {
    const preset = presets.find(p => p.cron === cron);
    if (preset) return preset.label;

    // Parse common cron patterns
    const parts = cron.split(' ');
    if (parts.length === 5) {
      const [minute, hour] = parts;
      const time = `${hour.padStart(2, '0')}:${minute.padStart(2, '0')}`;

      if (parts[4] === '*' && parts[3] === '*' && parts[2] === '*') {
        return `Daily at ${time}`;
      }
      if (parts[4] !== '*') {
        const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
        return `Weekly on ${days[parseInt(parts[4])]} at ${time}`;
      }
      if (parts[2] !== '*') {
        return `Monthly on day ${parts[2]} at ${time}`;
      }
    }
    return cron;
  };

  const getReportTypeLabel = (type: string): string => {
    return REPORT_TYPES.find(t => t.value === type)?.label || type;
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

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-primary" />
            <h3 className="text-xl font-semibold text-white">Scheduled Reports</h3>
          </div>
          {!showForm && (
            <Button variant="primary" onClick={() => setShowForm(true)}>
              <Plus className="h-4 w-4 mr-2" />
              New Scheduled Report
            </Button>
          )}
        </div>
        <p className="text-sm text-slate-400 mt-2">
          Automatically generate and email reports on a schedule
        </p>
      </Card>

      {showForm && (
        <Card>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-medium text-white">
                {editingId ? 'Edit Scheduled Report' : 'Create Scheduled Report'}
              </h4>
              <button type="button" onClick={resetForm} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="Weekly Vulnerability Report"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Description</label>
                <input
                  type="text"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="Optional description"
                />
              </div>
            </div>

            {/* Report Type & Format */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Report Type</label>
                <select
                  value={formData.report_type}
                  onChange={(e) => setFormData({ ...formData, report_type: e.target.value })}
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white"
                >
                  {REPORT_TYPES.map(type => (
                    <option key={type.value} value={type.value}>{type.label}</option>
                  ))}
                </select>
                <p className="text-xs text-slate-500 mt-1">
                  {REPORT_TYPES.find(t => t.value === formData.report_type)?.description}
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Format</label>
                <div className="flex gap-2">
                  {FORMATS.map(fmt => (
                    <button
                      key={fmt.value}
                      type="button"
                      onClick={() => setFormData({ ...formData, format: fmt.value })}
                      className={`flex-1 px-4 py-2 rounded-lg border transition-colors ${
                        formData.format === fmt.value
                          ? 'bg-primary/20 border-primary text-primary'
                          : 'bg-dark-bg border-dark-border text-slate-400 hover:border-slate-500'
                      }`}
                    >
                      {fmt.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Schedule Configuration */}
            <div className="p-4 bg-dark-bg rounded-lg border border-dark-border">
              <h5 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                <Calendar className="h-4 w-4" /> Schedule
              </h5>
              <div className="space-y-3">
                <div className="flex flex-wrap gap-2">
                  {presets.map(preset => (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => {
                        setFormData({ ...formData, schedule: preset.cron });
                        setUseCustomCron(false);
                      }}
                      className={`px-3 py-1.5 rounded-lg border text-sm transition-colors ${
                        formData.schedule === preset.cron && !useCustomCron
                          ? 'bg-primary/20 border-primary text-primary'
                          : 'bg-dark-surface border-dark-border text-slate-400 hover:border-slate-500'
                      }`}
                      title={preset.description}
                    >
                      {preset.label}
                    </button>
                  ))}
                  <button
                    type="button"
                    onClick={() => setUseCustomCron(true)}
                    className={`px-3 py-1.5 rounded-lg border text-sm transition-colors ${
                      useCustomCron
                        ? 'bg-primary/20 border-primary text-primary'
                        : 'bg-dark-surface border-dark-border text-slate-400 hover:border-slate-500'
                    }`}
                  >
                    Custom
                  </button>
                </div>
                {useCustomCron && (
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Cron Expression</label>
                    <input
                      type="text"
                      value={formData.schedule}
                      onChange={(e) => setFormData({ ...formData, schedule: e.target.value })}
                      className="w-full bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-white font-mono text-sm"
                      placeholder="0 8 * * *"
                    />
                    <p className="text-xs text-slate-500 mt-1">
                      Format: minute hour day-of-month month day-of-week (e.g., "0 8 * * *" for daily at 8am)
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Recipients */}
            <div className="p-4 bg-dark-bg rounded-lg border border-dark-border">
              <h5 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                <Mail className="h-4 w-4" /> Recipients
              </h5>
              <div className="flex gap-2 mb-3">
                <input
                  type="email"
                  value={newRecipient}
                  onChange={(e) => setNewRecipient(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      handleAddRecipient();
                    }
                  }}
                  className="flex-1 bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-white"
                  placeholder="email@example.com"
                />
                <Button type="button" variant="secondary" onClick={handleAddRecipient}>
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              {formData.recipients.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {formData.recipients.map(email => (
                    <span
                      key={email}
                      className="inline-flex items-center gap-1 px-2 py-1 bg-dark-surface rounded-lg text-sm text-slate-300"
                    >
                      <Mail className="h-3 w-3" />
                      {email}
                      <button
                        type="button"
                        onClick={() => handleRemoveRecipient(email)}
                        className="ml-1 text-slate-500 hover:text-red-400"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-500">No recipients added</p>
              )}
            </div>

            {/* Filters - based on report type */}
            <div className="p-4 bg-dark-bg rounded-lg border border-dark-border">
              <h5 className="text-sm font-medium text-slate-300 mb-3">Filters</h5>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Time Period</label>
                  <select
                    value={formData.filters.days_back || 30}
                    onChange={(e) => setFormData({
                      ...formData,
                      filters: { ...formData.filters, days_back: parseInt(e.target.value) }
                    })}
                    className="w-full bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-white"
                  >
                    <option value={7}>Last 7 days</option>
                    <option value={14}>Last 14 days</option>
                    <option value={30}>Last 30 days</option>
                    <option value={60}>Last 60 days</option>
                    <option value={90}>Last 90 days</option>
                  </select>
                </div>

                {formData.report_type === 'vulnerability' && (
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Minimum Severity</label>
                    <select
                      value={formData.filters.min_severity || ''}
                      onChange={(e) => setFormData({
                        ...formData,
                        filters: { ...formData.filters, min_severity: e.target.value || undefined }
                      })}
                      className="w-full bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-white"
                    >
                      {SEVERITY_OPTIONS.map(opt => (
                        <option key={opt.value} value={opt.value}>{opt.label}</option>
                      ))}
                    </select>
                  </div>
                )}

                {formData.report_type === 'compliance' && (
                  <div className="md:col-span-2">
                    <label className="block text-xs text-slate-400 mb-1">Frameworks</label>
                    <div className="flex flex-wrap gap-2">
                      {FRAMEWORKS.map(fw => (
                        <button
                          key={fw.value}
                          type="button"
                          onClick={() => {
                            const current = formData.filters.frameworks || [];
                            const updated = current.includes(fw.value)
                              ? current.filter(f => f !== fw.value)
                              : [...current, fw.value];
                            setFormData({
                              ...formData,
                              filters: { ...formData.filters, frameworks: updated }
                            });
                          }}
                          className={`px-2 py-1 rounded text-xs border transition-colors ${
                            formData.filters.frameworks?.includes(fw.value)
                              ? 'bg-primary/20 border-primary text-primary'
                              : 'bg-dark-surface border-dark-border text-slate-400 hover:border-slate-500'
                          }`}
                        >
                          {fw.label}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="include_charts"
                    checked={formData.include_charts}
                    onChange={(e) => setFormData({ ...formData, include_charts: e.target.checked })}
                    className="w-4 h-4 rounded border-dark-border bg-dark-bg text-primary focus:ring-primary"
                  />
                  <label htmlFor="include_charts" className="text-sm text-slate-300">
                    Include charts and visualizations
                  </label>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <Button type="button" variant="secondary" onClick={resetForm}>
                Cancel
              </Button>
              <Button type="submit" variant="primary">
                <Save className="h-4 w-4 mr-2" />
                {editingId ? 'Update' : 'Create'}
              </Button>
            </div>
          </form>
        </Card>
      )}

      {reports.length === 0 && !showForm ? (
        <Card>
          <div className="text-center py-12">
            <FileText className="h-12 w-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">No scheduled reports</p>
            <p className="text-sm text-slate-500 mt-1">
              Create automated reports to receive regular updates via email
            </p>
          </div>
        </Card>
      ) : (
        <div className="space-y-3">
          {reports.map((report) => {
            const recipients = JSON.parse(report.recipients);
            return (
              <Card key={report.id}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div
                      className={`p-2 rounded-lg ${
                        report.is_active ? 'bg-green-500/20' : 'bg-slate-500/20'
                      }`}
                    >
                      <FileText
                        className={`h-5 w-5 ${
                          report.is_active ? 'text-green-400' : 'text-slate-400'
                        }`}
                      />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="font-medium text-white">{report.name}</h4>
                        <Badge
                          variant="status"
                          type={report.is_active ? 'completed' : 'pending'}
                        >
                          {report.is_active ? 'Active' : 'Paused'}
                        </Badge>
                        <Badge variant="primary">
                          {report.format.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-sm text-slate-400">
                        {getReportTypeLabel(report.report_type)} - {formatSchedule(report.schedule)}
                      </p>
                      <p className="text-xs text-slate-500 mt-1">
                        <span className="inline-flex items-center gap-1">
                          <Mail className="h-3 w-3" />
                          {recipients.length} recipient{recipients.length !== 1 ? 's' : ''}
                        </span>
                        {report.last_run_at && (
                          <span className="ml-3">
                            <Clock className="h-3 w-3 inline mr-1" />
                            Last run {formatDistanceToNow(new Date(report.last_run_at))} ago
                          </span>
                        )}
                        <span className="ml-3">
                          Next: {new Date(report.next_run_at).toLocaleString()}
                        </span>
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleRunNow(report)}
                      disabled={runningReportId === report.id}
                      className="p-2 text-cyan-400 hover:bg-cyan-500/20 rounded transition-colors disabled:opacity-50"
                      title="Run Now"
                    >
                      {runningReportId === report.id ? (
                        <LoadingSpinner size="sm" />
                      ) : (
                        <Send className="h-4 w-4" />
                      )}
                    </button>
                    <button
                      onClick={() => handleToggleActive(report)}
                      className={`p-2 rounded transition-colors ${
                        report.is_active
                          ? 'text-yellow-400 hover:bg-yellow-500/20'
                          : 'text-green-400 hover:bg-green-500/20'
                      }`}
                      title={report.is_active ? 'Pause' : 'Activate'}
                    >
                      {report.is_active ? (
                        <Pause className="h-4 w-4" />
                      ) : (
                        <Play className="h-4 w-4" />
                      )}
                    </button>
                    <button
                      onClick={() => handleEdit(report)}
                      className="p-2 text-slate-400 hover:text-primary transition-colors"
                    >
                      <Edit2 className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => setDeleteConfirm(report)}
                      className="p-2 text-slate-400 hover:text-red-400 transition-colors"
                      aria-label={`Delete scheduled report ${report.name}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      <ConfirmationDialog
        isOpen={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={handleDelete}
        title="Delete Scheduled Report"
        message={`Are you sure you want to delete the scheduled report "${deleteConfirm?.name}"? Future reports will no longer be generated.`}
        confirmLabel="Delete Report"
        variant="warning"
        loading={isDeleting}
      />
    </div>
  );
};

export default ScheduledReports;
