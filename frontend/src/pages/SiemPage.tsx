import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  Server,
  Search,
  Shield,
  Bell,
  Plus,
  RefreshCw,
  Trash2,
  Edit,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Zap,
  Database,
  Filter,
  ChevronDown,
  ChevronRight,
  AlertCircle,
  Eye,
  Settings,
  Play,
  Pause,
  MoreVertical,
  X,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { Layout } from '../components/layout/Layout';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { siemFullAPI } from '../services/api';
import type {
  SiemLogSource,
  CreateSiemLogSourceRequest,
  UpdateSiemLogSourceRequest,
  SiemLogEntry,
  SiemLogSearchParams,
  SiemRule,
  CreateSiemRuleRequest,
  UpdateSiemRuleRequest,
  SiemAlert,
  SiemStatsResponse,
} from '../types';

type TabType = 'dashboard' | 'sources' | 'logs' | 'rules' | 'alerts';

const severityColors: Record<string, { bg: string; text: string; border: string }> = {
  debug: { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500' },
  info: { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500' },
  notice: { bg: 'bg-cyan-500/20', text: 'text-cyan-400', border: 'border-cyan-500' },
  warning: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500' },
  error: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500' },
  critical: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500' },
  alert: { bg: 'bg-red-600/20', text: 'text-red-500', border: 'border-red-600' },
  emergency: { bg: 'bg-purple-500/20', text: 'text-purple-400', border: 'border-purple-500' },
};

const statusColors: Record<string, { bg: string; text: string }> = {
  pending: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  active: { bg: 'bg-green-500/20', text: 'text-green-400' },
  inactive: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  error: { bg: 'bg-red-500/20', text: 'text-red-400' },
  enabled: { bg: 'bg-green-500/20', text: 'text-green-400' },
  disabled: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  testing: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  new: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  in_progress: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  escalated: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  resolved: { bg: 'bg-green-500/20', text: 'text-green-400' },
  false_positive: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  ignored: { bg: 'bg-gray-600/20', text: 'text-gray-500' },
};

// Modal component for forms
const Modal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}> = ({ isOpen, onClose, title, children }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="relative bg-dark-surface border border-dark-border rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-dark-border">
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <button
            onClick={onClose}
            className="p-1 rounded-lg hover:bg-dark-hover text-gray-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
};

// Log Source Form component
const LogSourceForm: React.FC<{
  source?: SiemLogSource;
  onSubmit: (data: CreateSiemLogSourceRequest | UpdateSiemLogSourceRequest) => void;
  onCancel: () => void;
  isLoading?: boolean;
}> = ({ source, onSubmit, onCancel, isLoading }) => {
  const [formData, setFormData] = useState({
    name: source?.name || '',
    description: source?.description || '',
    source_type: source?.source_type || 'syslog',
    host: source?.host || '',
    format: (source?.format as string) || 'syslog_rfc5424',
    protocol: (source?.protocol as string) || 'udp',
    port: source?.port?.toString() || '514',
    auto_enrich: source?.auto_enrich ?? true,
    retention_days: source?.retention_days?.toString() || '90',
    tags: source?.tags?.join(', ') || '',
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      name: formData.name,
      description: formData.description || undefined,
      source_type: formData.source_type,
      host: formData.host || undefined,
      format: formData.format,
      protocol: formData.protocol,
      port: formData.port ? parseInt(formData.port) : undefined,
      auto_enrich: formData.auto_enrich,
      retention_days: formData.retention_days ? parseInt(formData.retention_days) : undefined,
      tags: formData.tags ? formData.tags.split(',').map((t) => t.trim()).filter(Boolean) : undefined,
    });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Name *</label>
          <input
            type="text"
            required
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
            placeholder="e.g., Firewall Logs"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Source Type</label>
          <select
            value={formData.source_type}
            onChange={(e) => setFormData({ ...formData, source_type: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
          >
            <option value="syslog">Syslog</option>
            <option value="windows">Windows Event</option>
            <option value="firewall">Firewall</option>
            <option value="ids">IDS/IPS</option>
            <option value="application">Application</option>
            <option value="database">Database</option>
            <option value="cloud">Cloud Service</option>
            <option value="endpoint">Endpoint</option>
            <option value="custom">Custom</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
          rows={2}
          placeholder="Optional description of the log source"
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Host</label>
          <input
            type="text"
            value={formData.host}
            onChange={(e) => setFormData({ ...formData, host: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
            placeholder="e.g., 192.168.1.1"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Protocol</label>
          <select
            value={formData.protocol}
            onChange={(e) => setFormData({ ...formData, protocol: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
          >
            <option value="udp">UDP</option>
            <option value="tcp">TCP</option>
            <option value="tcp_tls">TCP+TLS</option>
            <option value="http">HTTP</option>
            <option value="https">HTTPS</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Port</label>
          <input
            type="number"
            value={formData.port}
            onChange={(e) => setFormData({ ...formData, port: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
            placeholder="514"
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Log Format</label>
          <select
            value={formData.format}
            onChange={(e) => setFormData({ ...formData, format: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
          >
            <option value="syslog_rfc5424">Syslog RFC5424</option>
            <option value="syslog_rfc3164">Syslog RFC3164 (BSD)</option>
            <option value="cef">CEF</option>
            <option value="leef">LEEF</option>
            <option value="json">JSON</option>
            <option value="windows_event">Windows Event</option>
            <option value="raw">Raw Text</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Retention (days)</label>
          <input
            type="number"
            value={formData.retention_days}
            onChange={(e) => setFormData({ ...formData, retention_days: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
            placeholder="90"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Tags (comma-separated)</label>
        <input
          type="text"
          value={formData.tags}
          onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
          className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
          placeholder="network, production, firewall"
        />
      </div>

      <div className="flex items-center gap-2">
        <input
          type="checkbox"
          id="auto_enrich"
          checked={formData.auto_enrich}
          onChange={(e) => setFormData({ ...formData, auto_enrich: e.target.checked })}
          className="w-4 h-4 rounded border-dark-border bg-dark-bg text-primary focus:ring-primary"
        />
        <label htmlFor="auto_enrich" className="text-sm text-gray-300">
          Enable automatic enrichment (GeoIP, threat intelligence, etc.)
        </label>
      </div>

      <div className="flex justify-end gap-3 pt-4 border-t border-dark-border">
        <Button type="button" variant="ghost" onClick={onCancel} disabled={isLoading}>
          Cancel
        </Button>
        <Button type="submit" disabled={isLoading}>
          {isLoading ? (
            <>
              <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              Saving...
            </>
          ) : (
            <>{source ? 'Update' : 'Create'} Log Source</>
          )}
        </Button>
      </div>
    </form>
  );
};

// Rule Form component
const RuleForm: React.FC<{
  rule?: SiemRule;
  logSources?: SiemLogSource[];
  onSubmit: (data: CreateSiemRuleRequest | UpdateSiemRuleRequest) => void;
  onCancel: () => void;
  isLoading?: boolean;
}> = ({ rule, logSources, onSubmit, onCancel, isLoading }) => {
  const [formData, setFormData] = useState({
    name: rule?.name || '',
    description: rule?.description || '',
    rule_type: (rule?.rule_type as string) || 'pattern',
    severity: (rule?.severity as string) || 'warning',
    status: (rule?.status as string) || 'disabled',
    definition: JSON.stringify(rule?.definition || { pattern: '' }, null, 2),
    source_ids: rule?.source_ids || [],
    mitre_tactics: rule?.mitre_tactics?.join(', ') || '',
    mitre_techniques: rule?.mitre_techniques?.join(', ') || '',
    tags: rule?.tags?.join(', ') || '',
    time_window_seconds: rule?.time_window_seconds?.toString() || '',
    threshold_count: rule?.threshold_count?.toString() || '',
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    let definition: Record<string, unknown> = {};
    try {
      definition = JSON.parse(formData.definition);
    } catch {
      toast.error('Invalid JSON in rule definition');
      return;
    }

    onSubmit({
      name: formData.name,
      description: formData.description || undefined,
      rule_type: formData.rule_type,
      severity: formData.severity,
      status: formData.status,
      definition,
      source_ids: formData.source_ids.length > 0 ? formData.source_ids : undefined,
      mitre_tactics: formData.mitre_tactics ? formData.mitre_tactics.split(',').map((t) => t.trim()).filter(Boolean) : undefined,
      mitre_techniques: formData.mitre_techniques ? formData.mitre_techniques.split(',').map((t) => t.trim()).filter(Boolean) : undefined,
      tags: formData.tags ? formData.tags.split(',').map((t) => t.trim()).filter(Boolean) : undefined,
      time_window_seconds: formData.time_window_seconds ? parseInt(formData.time_window_seconds) : undefined,
      threshold_count: formData.threshold_count ? parseInt(formData.threshold_count) : undefined,
    });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Name *</label>
          <input
            type="text"
            required
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
            placeholder="e.g., Brute Force Detection"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Rule Type</label>
          <select
            value={formData.rule_type}
            onChange={(e) => setFormData({ ...formData, rule_type: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
          >
            <option value="pattern">Pattern Match</option>
            <option value="regex">Regular Expression</option>
            <option value="threshold">Threshold</option>
            <option value="correlation">Correlation</option>
            <option value="anomaly">Anomaly Detection</option>
            <option value="sigma">Sigma Rule</option>
            <option value="yara">YARA Rule</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
          rows={2}
          placeholder="What does this rule detect?"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Severity</label>
          <select
            value={formData.severity}
            onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
          >
            <option value="debug">Debug</option>
            <option value="info">Info</option>
            <option value="notice">Notice</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
            <option value="critical">Critical</option>
            <option value="alert">Alert</option>
            <option value="emergency">Emergency</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Status</label>
          <select
            value={formData.status}
            onChange={(e) => setFormData({ ...formData, status: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
          >
            <option value="disabled">Disabled</option>
            <option value="testing">Testing</option>
            <option value="enabled">Enabled</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Rule Definition (JSON) *</label>
        <textarea
          value={formData.definition}
          onChange={(e) => setFormData({ ...formData, definition: e.target.value })}
          className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white font-mono text-sm focus:ring-2 focus:ring-primary focus:border-primary"
          rows={6}
          placeholder='{"pattern": "failed login", "field": "message"}'
        />
      </div>

      {logSources && logSources.length > 0 && (
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Apply to Log Sources</label>
          <div className="flex flex-wrap gap-2 p-3 bg-dark-bg border border-dark-border rounded-lg max-h-32 overflow-y-auto">
            {logSources.map((source) => (
              <label key={source.id} className="flex items-center gap-2 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={formData.source_ids.includes(source.id)}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setFormData({ ...formData, source_ids: [...formData.source_ids, source.id] });
                    } else {
                      setFormData({ ...formData, source_ids: formData.source_ids.filter((id) => id !== source.id) });
                    }
                  }}
                  className="w-4 h-4 rounded border-dark-border bg-dark-bg text-primary focus:ring-primary"
                />
                {source.name}
              </label>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Time Window (seconds)</label>
          <input
            type="number"
            value={formData.time_window_seconds}
            onChange={(e) => setFormData({ ...formData, time_window_seconds: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
            placeholder="300"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Threshold Count</label>
          <input
            type="number"
            value={formData.threshold_count}
            onChange={(e) => setFormData({ ...formData, threshold_count: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
            placeholder="5"
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">MITRE Tactics (comma-separated)</label>
          <input
            type="text"
            value={formData.mitre_tactics}
            onChange={(e) => setFormData({ ...formData, mitre_tactics: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
            placeholder="TA0001, TA0002"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Tags (comma-separated)</label>
          <input
            type="text"
            value={formData.tags}
            onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
            className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-primary"
            placeholder="brute-force, authentication"
          />
        </div>
      </div>

      <div className="flex justify-end gap-3 pt-4 border-t border-dark-border">
        <Button type="button" variant="ghost" onClick={onCancel} disabled={isLoading}>
          Cancel
        </Button>
        <Button type="submit" disabled={isLoading}>
          {isLoading ? (
            <>
              <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              Saving...
            </>
          ) : (
            <>{rule ? 'Update' : 'Create'} Rule</>
          )}
        </Button>
      </div>
    </form>
  );
};

export default function SiemPage() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [showSourceModal, setShowSourceModal] = useState(false);
  const [editingSource, setEditingSource] = useState<SiemLogSource | undefined>();
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [editingRule, setEditingRule] = useState<SiemRule | undefined>();
  const [selectedLogEntry, setSelectedLogEntry] = useState<SiemLogEntry | null>(null);
  const [logSearchParams, setLogSearchParams] = useState<SiemLogSearchParams>({
    limit: 50,
    offset: 0,
  });
  const queryClient = useQueryClient();

  // Fetch SIEM stats
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['siemStats'],
    queryFn: () => siemFullAPI.getStats().then((res) => res.data),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Fetch log sources
  const { data: logSources, isLoading: sourcesLoading } = useQuery({
    queryKey: ['siemLogSources'],
    queryFn: () => siemFullAPI.listLogSources().then((res) => res.data),
  });

  // Fetch logs
  const { data: logsData, isLoading: logsLoading } = useQuery({
    queryKey: ['siemLogs', logSearchParams],
    queryFn: () => siemFullAPI.queryLogs(logSearchParams).then((res) => res.data),
    enabled: activeTab === 'logs',
  });

  // Fetch rules
  const { data: rules, isLoading: rulesLoading } = useQuery({
    queryKey: ['siemRules'],
    queryFn: () => siemFullAPI.listRules().then((res) => res.data),
  });

  // Fetch alerts
  const { data: alerts, isLoading: alertsLoading } = useQuery({
    queryKey: ['siemAlerts'],
    queryFn: () => siemFullAPI.listAlerts({ limit: 100 }).then((res) => res.data),
  });

  // Mutations
  const createSourceMutation = useMutation({
    mutationFn: (data: CreateSiemLogSourceRequest) => siemFullAPI.createLogSource(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siemLogSources'] });
      queryClient.invalidateQueries({ queryKey: ['siemStats'] });
      toast.success('Log source created successfully');
      setShowSourceModal(false);
    },
    onError: () => toast.error('Failed to create log source'),
  });

  const updateSourceMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateSiemLogSourceRequest }) =>
      siemFullAPI.updateLogSource(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siemLogSources'] });
      toast.success('Log source updated');
      setShowSourceModal(false);
      setEditingSource(undefined);
    },
    onError: () => toast.error('Failed to update log source'),
  });

  const deleteSourceMutation = useMutation({
    mutationFn: (id: string) => siemFullAPI.deleteLogSource(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siemLogSources'] });
      queryClient.invalidateQueries({ queryKey: ['siemStats'] });
      toast.success('Log source deleted');
    },
    onError: () => toast.error('Failed to delete log source'),
  });

  const createRuleMutation = useMutation({
    mutationFn: (data: CreateSiemRuleRequest) => siemFullAPI.createRule(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siemRules'] });
      queryClient.invalidateQueries({ queryKey: ['siemStats'] });
      toast.success('Rule created successfully');
      setShowRuleModal(false);
    },
    onError: () => toast.error('Failed to create rule'),
  });

  const updateRuleMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateSiemRuleRequest }) =>
      siemFullAPI.updateRule(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siemRules'] });
      toast.success('Rule updated');
      setShowRuleModal(false);
      setEditingRule(undefined);
    },
    onError: () => toast.error('Failed to update rule'),
  });

  const deleteRuleMutation = useMutation({
    mutationFn: (id: string) => siemFullAPI.deleteRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siemRules'] });
      queryClient.invalidateQueries({ queryKey: ['siemStats'] });
      toast.success('Rule deleted');
    },
    onError: () => toast.error('Failed to delete rule'),
  });

  const updateAlertMutation = useMutation({
    mutationFn: ({ id, status, assigned_to }: { id: string; status: string; assigned_to?: string }) =>
      siemFullAPI.updateAlertStatus(id, { status, assigned_to }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siemAlerts'] });
      queryClient.invalidateQueries({ queryKey: ['siemStats'] });
      toast.success('Alert updated');
    },
    onError: () => toast.error('Failed to update alert'),
  });

  const resolveAlertMutation = useMutation({
    mutationFn: ({ id, resolution_notes, is_false_positive }: { id: string; resolution_notes?: string; is_false_positive?: boolean }) =>
      siemFullAPI.resolveAlert(id, { resolution_notes, is_false_positive }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siemAlerts'] });
      queryClient.invalidateQueries({ queryKey: ['siemStats'] });
      toast.success('Alert resolved');
    },
    onError: () => toast.error('Failed to resolve alert'),
  });

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <Activity className="w-4 h-4" /> },
    { id: 'sources', label: 'Log Sources', icon: <Server className="w-4 h-4" /> },
    { id: 'logs', label: 'Log Search', icon: <Search className="w-4 h-4" /> },
    { id: 'rules', label: 'Detection Rules', icon: <Shield className="w-4 h-4" /> },
    { id: 'alerts', label: 'Alerts', icon: <Bell className="w-4 h-4" /> },
  ];

  const formatNumber = (n: number) => {
    if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
    if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
    return n.toString();
  };

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
              <Activity className="w-8 h-8 text-primary" />
              SIEM Dashboard
            </h1>
            <p className="text-slate-600 dark:text-gray-400 mt-1">
              Security Information and Event Management - Log collection, detection, and alerting
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-light-border dark:border-dark-border">
          <nav className="flex gap-4">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-primary text-primary'
                    : 'border-transparent text-slate-600 dark:text-gray-400 hover:text-slate-900 dark:hover:text-gray-200'
                }`}
              >
                {tab.icon}
                {tab.label}
                {tab.id === 'alerts' && alerts && alerts.filter((a) => a.status === 'new').length > 0 && (
                  <span className="ml-1 px-2 py-0.5 text-xs rounded-full bg-red-500 text-white">
                    {alerts.filter((a) => a.status === 'new').length}
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div>
          {/* Dashboard Tab */}
          {activeTab === 'dashboard' && (
            <div className="space-y-6">
              {statsLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-primary animate-spin" />
                </div>
              ) : stats ? (
                <>
                  {/* Stats Cards */}
                  <div className="grid grid-cols-4 gap-4">
                    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-blue-500/20 rounded-lg">
                          <Server className="w-6 h-6 text-blue-400" />
                        </div>
                        <div>
                          <p className="text-sm text-slate-600 dark:text-gray-400">Log Sources</p>
                          <p className="text-2xl font-bold text-slate-900 dark:text-white">{stats.total_sources}</p>
                          <p className="text-xs text-green-400">{stats.active_sources} active</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-purple-500/20 rounded-lg">
                          <Database className="w-6 h-6 text-purple-400" />
                        </div>
                        <div>
                          <p className="text-sm text-slate-600 dark:text-gray-400">Logs Today</p>
                          <p className="text-2xl font-bold text-slate-900 dark:text-white">{formatNumber(stats.total_logs_today)}</p>
                          <p className="text-xs text-slate-500 dark:text-gray-500">{stats.ingestion_rate.toFixed(1)}/sec</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-cyan-500/20 rounded-lg">
                          <Shield className="w-6 h-6 text-cyan-400" />
                        </div>
                        <div>
                          <p className="text-sm text-slate-600 dark:text-gray-400">Detection Rules</p>
                          <p className="text-2xl font-bold text-slate-900 dark:text-white">{stats.total_rules}</p>
                          <p className="text-xs text-green-400">{stats.enabled_rules} enabled</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-red-500/20 rounded-lg">
                          <Bell className="w-6 h-6 text-red-400" />
                        </div>
                        <div>
                          <p className="text-sm text-slate-600 dark:text-gray-400">Open Alerts</p>
                          <p className="text-2xl font-bold text-slate-900 dark:text-white">{stats.open_alerts}</p>
                          <p className="text-xs text-red-400">{stats.critical_alerts} critical</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Charts Row */}
                  <div className="grid grid-cols-2 gap-6">
                    {/* Alerts by Status */}
                    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Alerts by Status</h3>
                      <div className="space-y-3">
                        {stats.alerts_by_status.map((item) => (
                          <div key={item.status} className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-1 rounded text-xs ${statusColors[item.status]?.bg || 'bg-gray-500/20'} ${statusColors[item.status]?.text || 'text-gray-400'}`}>
                                {item.status.replace('_', ' ')}
                              </span>
                            </div>
                            <span className="text-slate-600 dark:text-gray-400">{item.count}</span>
                          </div>
                        ))}
                        {stats.alerts_by_status.length === 0 && (
                          <p className="text-slate-500 dark:text-gray-500 text-sm">No alerts yet</p>
                        )}
                      </div>
                    </div>

                    {/* Alerts by Severity */}
                    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Alerts by Severity</h3>
                      <div className="space-y-3">
                        {stats.alerts_by_severity.map((item) => (
                          <div key={item.severity} className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-1 rounded text-xs ${severityColors[item.severity]?.bg || 'bg-gray-500/20'} ${severityColors[item.severity]?.text || 'text-gray-400'}`}>
                                {item.severity}
                              </span>
                            </div>
                            <span className="text-slate-600 dark:text-gray-400">{item.count}</span>
                          </div>
                        ))}
                        {stats.alerts_by_severity.length === 0 && (
                          <p className="text-slate-500 dark:text-gray-500 text-sm">No alerts yet</p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Top Log Sources */}
                  <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Top Log Sources</h3>
                    <div className="space-y-3">
                      {stats.top_sources.map((source) => (
                        <div key={source.id} className="flex items-center justify-between p-3 bg-light-bg dark:bg-dark-bg rounded-lg">
                          <div className="flex items-center gap-3">
                            <Server className="w-5 h-5 text-slate-400 dark:text-gray-500" />
                            <span className="text-slate-700 dark:text-gray-300">{source.name}</span>
                          </div>
                          <div className="text-right">
                            <p className="text-slate-900 dark:text-white font-medium">{formatNumber(source.log_count)} logs</p>
                            <p className="text-xs text-slate-500 dark:text-gray-500">{source.logs_per_hour}/hr</p>
                          </div>
                        </div>
                      ))}
                      {stats.top_sources.length === 0 && (
                        <p className="text-slate-500 dark:text-gray-500 text-sm text-center py-4">No log sources configured yet</p>
                      )}
                    </div>
                  </div>
                </>
              ) : (
                <div className="text-center py-12">
                  <AlertCircle className="w-16 h-16 text-slate-400 dark:text-gray-600 mx-auto mb-4" />
                  <p className="text-slate-600 dark:text-gray-400">Failed to load statistics</p>
                </div>
              )}
            </div>
          )}

          {/* Log Sources Tab */}
          {activeTab === 'sources' && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <Button onClick={() => { setEditingSource(undefined); setShowSourceModal(true); }}>
                  <Plus className="w-4 h-4 mr-2" />
                  Add Log Source
                </Button>
              </div>

              {sourcesLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-primary animate-spin" />
                </div>
              ) : logSources && logSources.length > 0 ? (
                <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-light-border dark:border-dark-border">
                        <th className="text-left p-4 text-sm font-medium text-slate-600 dark:text-gray-400">Name</th>
                        <th className="text-left p-4 text-sm font-medium text-slate-600 dark:text-gray-400">Type</th>
                        <th className="text-left p-4 text-sm font-medium text-slate-600 dark:text-gray-400">Host</th>
                        <th className="text-left p-4 text-sm font-medium text-slate-600 dark:text-gray-400">Status</th>
                        <th className="text-left p-4 text-sm font-medium text-slate-600 dark:text-gray-400">Logs</th>
                        <th className="text-left p-4 text-sm font-medium text-slate-600 dark:text-gray-400">Last Seen</th>
                        <th className="text-right p-4 text-sm font-medium text-slate-600 dark:text-gray-400">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {logSources.map((source) => (
                        <tr key={source.id} className="border-b border-light-border dark:border-dark-border hover:bg-light-hover dark:hover:bg-dark-hover">
                          <td className="p-4">
                            <div>
                              <p className="font-medium text-slate-900 dark:text-white">{source.name}</p>
                              {source.description && (
                                <p className="text-xs text-slate-500 dark:text-gray-500 truncate max-w-xs">{source.description}</p>
                              )}
                            </div>
                          </td>
                          <td className="p-4 text-slate-600 dark:text-gray-400">{source.source_type}</td>
                          <td className="p-4 text-slate-600 dark:text-gray-400">{source.host || '-'}</td>
                          <td className="p-4">
                            <span className={`px-2 py-1 rounded text-xs ${statusColors[source.status]?.bg || 'bg-gray-500/20'} ${statusColors[source.status]?.text || 'text-gray-400'}`}>
                              {source.status}
                            </span>
                          </td>
                          <td className="p-4 text-slate-600 dark:text-gray-400">{formatNumber(source.log_count)}</td>
                          <td className="p-4 text-slate-500 dark:text-gray-500 text-sm">
                            {source.last_seen ? new Date(source.last_seen).toLocaleString() : 'Never'}
                          </td>
                          <td className="p-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => { setEditingSource(source); setShowSourceModal(true); }}
                                className="p-2 hover:bg-light-hover dark:hover:bg-dark-hover rounded-lg text-slate-500 dark:text-gray-400 hover:text-slate-700 dark:hover:text-white"
                              >
                                <Edit className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => {
                                  if (confirm('Delete this log source?')) {
                                    deleteSourceMutation.mutate(source.id);
                                  }
                                }}
                                className="p-2 hover:bg-red-500/20 rounded-lg text-slate-500 dark:text-gray-400 hover:text-red-400"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-12 text-center">
                  <Server className="w-16 h-16 text-slate-400 dark:text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-slate-700 dark:text-gray-300 mb-2">No Log Sources Configured</h3>
                  <p className="text-slate-500 dark:text-gray-400 mb-6">
                    Add log sources to start collecting and analyzing security events
                  </p>
                  <Button onClick={() => setShowSourceModal(true)}>
                    <Plus className="w-4 h-4 mr-2" />
                    Add Log Source
                  </Button>
                </div>
              )}
            </div>
          )}

          {/* Log Search Tab */}
          {activeTab === 'logs' && (
            <div className="space-y-4">
              {/* Search Filters */}
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                <div className="grid grid-cols-4 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-600 dark:text-gray-400 mb-1">Search</label>
                    <input
                      type="text"
                      value={logSearchParams.query || ''}
                      onChange={(e) => setLogSearchParams({ ...logSearchParams, query: e.target.value || undefined })}
                      className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                      placeholder="Search logs..."
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-600 dark:text-gray-400 mb-1">Min Severity</label>
                    <select
                      value={logSearchParams.min_severity || ''}
                      onChange={(e) => setLogSearchParams({ ...logSearchParams, min_severity: e.target.value || undefined })}
                      className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                    >
                      <option value="">All</option>
                      <option value="debug">Debug+</option>
                      <option value="info">Info+</option>
                      <option value="warning">Warning+</option>
                      <option value="error">Error+</option>
                      <option value="critical">Critical+</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-600 dark:text-gray-400 mb-1">Source IP</label>
                    <input
                      type="text"
                      value={logSearchParams.source_ip || ''}
                      onChange={(e) => setLogSearchParams({ ...logSearchParams, source_ip: e.target.value || undefined })}
                      className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                      placeholder="192.168.1.1"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-600 dark:text-gray-400 mb-1">Hostname</label>
                    <input
                      type="text"
                      value={logSearchParams.hostname || ''}
                      onChange={(e) => setLogSearchParams({ ...logSearchParams, hostname: e.target.value || undefined })}
                      className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                      placeholder="server01"
                    />
                  </div>
                </div>
                <div className="flex justify-end mt-4">
                  <Button
                    size="sm"
                    onClick={() => queryClient.invalidateQueries({ queryKey: ['siemLogs'] })}
                  >
                    <Search className="w-4 h-4 mr-2" />
                    Search
                  </Button>
                </div>
              </div>

              {/* Results */}
              {logsLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-primary animate-spin" />
                </div>
              ) : logsData ? (
                <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
                  <div className="p-4 border-b border-light-border dark:border-dark-border flex items-center justify-between">
                    <p className="text-sm text-slate-600 dark:text-gray-400">
                      Showing {logsData.entries.length} of {logsData.total_count} logs ({logsData.query_time_ms}ms)
                    </p>
                  </div>
                  <div className="divide-y divide-light-border dark:divide-dark-border max-h-[600px] overflow-y-auto">
                    {logsData.entries.map((entry) => (
                      <div
                        key={entry.id}
                        className="p-3 hover:bg-light-hover dark:hover:bg-dark-hover cursor-pointer"
                        onClick={() => setSelectedLogEntry(entry)}
                      >
                        <div className="flex items-start gap-3">
                          <span className={`px-2 py-0.5 rounded text-xs ${severityColors[entry.severity]?.bg || 'bg-gray-500/20'} ${severityColors[entry.severity]?.text || 'text-gray-400'}`}>
                            {entry.severity}
                          </span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-gray-500 mb-1">
                              <span>{new Date(entry.timestamp).toLocaleString()}</span>
                              {entry.hostname && <span className="text-slate-400 dark:text-gray-600">|</span>}
                              {entry.hostname && <span>{entry.hostname}</span>}
                              {entry.application && <span className="text-slate-400 dark:text-gray-600">|</span>}
                              {entry.application && <span>{entry.application}</span>}
                            </div>
                            <p className="text-sm text-slate-700 dark:text-gray-300 truncate">{entry.message}</p>
                          </div>
                          {entry.alerted && (
                            <Bell className="w-4 h-4 text-red-400 flex-shrink-0" />
                          )}
                        </div>
                      </div>
                    ))}
                    {logsData.entries.length === 0 && (
                      <div className="p-12 text-center">
                        <Search className="w-12 h-12 text-slate-400 dark:text-gray-600 mx-auto mb-4" />
                        <p className="text-slate-500 dark:text-gray-400">No logs found matching your criteria</p>
                      </div>
                    )}
                  </div>
                </div>
              ) : null}
            </div>
          )}

          {/* Detection Rules Tab */}
          {activeTab === 'rules' && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <Button onClick={() => { setEditingRule(undefined); setShowRuleModal(true); }}>
                  <Plus className="w-4 h-4 mr-2" />
                  Add Rule
                </Button>
              </div>

              {rulesLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-primary animate-spin" />
                </div>
              ) : rules && rules.length > 0 ? (
                <div className="space-y-3">
                  {rules.map((rule) => (
                    <div
                      key={rule.id}
                      className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <h3 className="font-medium text-slate-900 dark:text-white">{rule.name}</h3>
                            <span className={`px-2 py-0.5 rounded text-xs ${statusColors[rule.status]?.bg || 'bg-gray-500/20'} ${statusColors[rule.status]?.text || 'text-gray-400'}`}>
                              {rule.status}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-xs ${severityColors[rule.severity]?.bg || 'bg-gray-500/20'} ${severityColors[rule.severity]?.text || 'text-gray-400'}`}>
                              {rule.severity}
                            </span>
                            <span className="px-2 py-0.5 rounded text-xs bg-slate-500/20 text-slate-400">
                              {rule.rule_type}
                            </span>
                          </div>
                          {rule.description && (
                            <p className="text-sm text-slate-500 dark:text-gray-400 mb-2">{rule.description}</p>
                          )}
                          <div className="flex items-center gap-4 text-xs text-slate-500 dark:text-gray-500">
                            <span>Triggered: {rule.trigger_count} times</span>
                            {rule.last_triggered && (
                              <span>Last: {new Date(rule.last_triggered).toLocaleString()}</span>
                            )}
                            {rule.mitre_tactics.length > 0 && (
                              <span>MITRE: {rule.mitre_tactics.join(', ')}</span>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => { setEditingRule(rule); setShowRuleModal(true); }}
                            className="p-2 hover:bg-light-hover dark:hover:bg-dark-hover rounded-lg text-slate-500 dark:text-gray-400 hover:text-slate-700 dark:hover:text-white"
                          >
                            <Edit className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => {
                              if (confirm('Delete this rule?')) {
                                deleteRuleMutation.mutate(rule.id);
                              }
                            }}
                            className="p-2 hover:bg-red-500/20 rounded-lg text-slate-500 dark:text-gray-400 hover:text-red-400"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-12 text-center">
                  <Shield className="w-16 h-16 text-slate-400 dark:text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-slate-700 dark:text-gray-300 mb-2">No Detection Rules</h3>
                  <p className="text-slate-500 dark:text-gray-400 mb-6">
                    Create detection rules to automatically identify security threats
                  </p>
                  <Button onClick={() => setShowRuleModal(true)}>
                    <Plus className="w-4 h-4 mr-2" />
                    Add Rule
                  </Button>
                </div>
              )}
            </div>
          )}

          {/* Alerts Tab */}
          {activeTab === 'alerts' && (
            <div className="space-y-4">
              {alertsLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-primary animate-spin" />
                </div>
              ) : alerts && alerts.length > 0 ? (
                <div className="space-y-3">
                  {alerts.map((alert) => (
                    <div
                      key={alert.id}
                      className={`bg-light-surface dark:bg-dark-surface border rounded-lg p-4 ${
                        severityColors[alert.severity]?.border ? `border-l-4 ${severityColors[alert.severity].border}` : 'border-dark-border'
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <h3 className="font-medium text-slate-900 dark:text-white">{alert.title}</h3>
                            <span className={`px-2 py-0.5 rounded text-xs ${statusColors[alert.status]?.bg || 'bg-gray-500/20'} ${statusColors[alert.status]?.text || 'text-gray-400'}`}>
                              {alert.status.replace('_', ' ')}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-xs ${severityColors[alert.severity]?.bg || 'bg-gray-500/20'} ${severityColors[alert.severity]?.text || 'text-gray-400'}`}>
                              {alert.severity}
                            </span>
                          </div>
                          {alert.description && (
                            <p className="text-sm text-slate-500 dark:text-gray-400 mb-2">{alert.description}</p>
                          )}
                          <div className="flex items-center gap-4 text-xs text-slate-500 dark:text-gray-500">
                            <span>Rule: {alert.rule_name}</span>
                            <span>Events: {alert.event_count}</span>
                            <span>First: {new Date(alert.first_seen).toLocaleString()}</span>
                            {alert.source_ips.length > 0 && (
                              <span>Sources: {alert.source_ips.slice(0, 3).join(', ')}{alert.source_ips.length > 3 ? '...' : ''}</span>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {alert.status !== 'resolved' && alert.status !== 'false_positive' && (
                            <>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => updateAlertMutation.mutate({ id: alert.id, status: 'in_progress' })}
                              >
                                Investigate
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => resolveAlertMutation.mutate({ id: alert.id })}
                              >
                                Resolve
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => resolveAlertMutation.mutate({ id: alert.id, is_false_positive: true })}
                              >
                                False Positive
                              </Button>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-12 text-center">
                  <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-slate-700 dark:text-gray-300 mb-2">No Alerts</h3>
                  <p className="text-slate-500 dark:text-gray-400">
                    Your detection rules have not triggered any alerts yet
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modals */}
        <Modal
          isOpen={showSourceModal}
          onClose={() => { setShowSourceModal(false); setEditingSource(undefined); }}
          title={editingSource ? 'Edit Log Source' : 'Add Log Source'}
        >
          <LogSourceForm
            source={editingSource}
            onSubmit={(data) => {
              if (editingSource) {
                updateSourceMutation.mutate({ id: editingSource.id, data: data as UpdateSiemLogSourceRequest });
              } else {
                createSourceMutation.mutate(data as CreateSiemLogSourceRequest);
              }
            }}
            onCancel={() => { setShowSourceModal(false); setEditingSource(undefined); }}
            isLoading={createSourceMutation.isPending || updateSourceMutation.isPending}
          />
        </Modal>

        <Modal
          isOpen={showRuleModal}
          onClose={() => { setShowRuleModal(false); setEditingRule(undefined); }}
          title={editingRule ? 'Edit Detection Rule' : 'Add Detection Rule'}
        >
          <RuleForm
            rule={editingRule}
            logSources={logSources}
            onSubmit={(data) => {
              if (editingRule) {
                updateRuleMutation.mutate({ id: editingRule.id, data: data as UpdateSiemRuleRequest });
              } else {
                createRuleMutation.mutate(data as CreateSiemRuleRequest);
              }
            }}
            onCancel={() => { setShowRuleModal(false); setEditingRule(undefined); }}
            isLoading={createRuleMutation.isPending || updateRuleMutation.isPending}
          />
        </Modal>

        {/* Log Entry Detail Modal */}
        <Modal
          isOpen={!!selectedLogEntry}
          onClose={() => setSelectedLogEntry(null)}
          title="Log Entry Details"
        >
          {selectedLogEntry && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-slate-500 dark:text-gray-500">Timestamp</label>
                  <p className="text-slate-900 dark:text-white">{new Date(selectedLogEntry.timestamp).toLocaleString()}</p>
                </div>
                <div>
                  <label className="text-sm text-slate-500 dark:text-gray-500">Severity</label>
                  <p>
                    <span className={`px-2 py-0.5 rounded text-xs ${severityColors[selectedLogEntry.severity]?.bg || 'bg-gray-500/20'} ${severityColors[selectedLogEntry.severity]?.text || 'text-gray-400'}`}>
                      {selectedLogEntry.severity}
                    </span>
                  </p>
                </div>
                <div>
                  <label className="text-sm text-slate-500 dark:text-gray-500">Hostname</label>
                  <p className="text-slate-900 dark:text-white">{selectedLogEntry.hostname || '-'}</p>
                </div>
                <div>
                  <label className="text-sm text-slate-500 dark:text-gray-500">Application</label>
                  <p className="text-slate-900 dark:text-white">{selectedLogEntry.application || '-'}</p>
                </div>
                <div>
                  <label className="text-sm text-slate-500 dark:text-gray-500">Source IP</label>
                  <p className="text-slate-900 dark:text-white">{selectedLogEntry.source_ip || '-'}</p>
                </div>
                <div>
                  <label className="text-sm text-slate-500 dark:text-gray-500">Destination IP</label>
                  <p className="text-slate-900 dark:text-white">{selectedLogEntry.destination_ip || '-'}</p>
                </div>
              </div>
              <div>
                <label className="text-sm text-slate-500 dark:text-gray-500">Message</label>
                <p className="text-slate-900 dark:text-white bg-light-bg dark:bg-dark-bg p-3 rounded-lg mt-1">{selectedLogEntry.message}</p>
              </div>
              <div>
                <label className="text-sm text-slate-500 dark:text-gray-500">Raw Log</label>
                <pre className="text-xs text-slate-700 dark:text-gray-300 bg-light-bg dark:bg-dark-bg p-3 rounded-lg mt-1 overflow-x-auto">{selectedLogEntry.raw}</pre>
              </div>
              {Object.keys(selectedLogEntry.structured_data).length > 0 && (
                <div>
                  <label className="text-sm text-slate-500 dark:text-gray-500">Structured Data</label>
                  <pre className="text-xs text-slate-700 dark:text-gray-300 bg-light-bg dark:bg-dark-bg p-3 rounded-lg mt-1 overflow-x-auto">
                    {JSON.stringify(selectedLogEntry.structured_data, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </Modal>
      </div>
    </Layout>
  );
}
