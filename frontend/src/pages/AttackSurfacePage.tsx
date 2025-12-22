import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Globe,
  Shield,
  Plus,
  Play,
  Pause,
  Trash2,
  RefreshCw,
  AlertTriangle,
  AlertCircle,
  CheckCircle,
  Clock,
  Eye,
  EyeOff,
  ChevronRight,
  Server,
  Activity,
  TrendingUp,
  Calendar,
  X,
  BarChart3,
  Target,
  Network,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { Layout } from '../components/layout/Layout';
import Button from '../components/ui/Button';
import { asmAPI } from '../services/api';
import type {
  AsmMonitor,
  AsmChange,
  AsmDashboard,
  AsmTimelineEvent,
  AsmAssetRiskScore,
  CreateAsmMonitorRequest,
  AsmAlertSeverity,
  AsmChangeType,
} from '../types';

// Severity badge colors
const getSeverityColor = (severity: AsmAlertSeverity) => {
  switch (severity) {
    case 'critical':
      return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'high':
      return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'medium':
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'low':
      return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    default:
      return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
  }
};

// Change type display
const getChangeTypeDisplay = (changeType: AsmChangeType) => {
  const types: Record<AsmChangeType, { label: string; color: string }> = {
    new_subdomain: { label: 'New Subdomain', color: 'text-green-400' },
    new_port: { label: 'New Port', color: 'text-green-400' },
    port_closed: { label: 'Port Closed', color: 'text-blue-400' },
    certificate_change: { label: 'Cert Change', color: 'text-yellow-400' },
    certificate_expiring: { label: 'Cert Expiring', color: 'text-orange-400' },
    technology_change: { label: 'Tech Change', color: 'text-purple-400' },
    ip_address_change: { label: 'IP Change', color: 'text-cyan-400' },
    asset_removed: { label: 'Asset Removed', color: 'text-red-400' },
    service_change: { label: 'Service Change', color: 'text-indigo-400' },
    shadow_it_detected: { label: 'Shadow IT', color: 'text-red-500' },
  };
  return types[changeType] || { label: changeType, color: 'text-slate-400' };
};

// Risk score gauge component
const RiskScoreGauge: React.FC<{ score: number; size?: 'sm' | 'md' | 'lg' }> = ({ score, size = 'md' }) => {
  const sizes = {
    sm: { width: 60, stroke: 4 },
    md: { width: 80, stroke: 6 },
    lg: { width: 120, stroke: 8 },
  };
  const { width, stroke } = sizes[size];
  const radius = (width - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;

  const getColor = () => {
    if (score >= 80) return 'text-red-500';
    if (score >= 60) return 'text-orange-500';
    if (score >= 40) return 'text-yellow-500';
    return 'text-green-500';
  };

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={width} height={width} className="-rotate-90">
        <circle
          cx={width / 2}
          cy={width / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={stroke}
          className="text-slate-700"
        />
        <circle
          cx={width / 2}
          cy={width / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={stroke}
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          strokeLinecap="round"
          className={getColor()}
        />
      </svg>
      <span className={`absolute text-${size === 'sm' ? 'xs' : size === 'md' ? 'sm' : 'lg'} font-bold text-white`}>
        {score}
      </span>
    </div>
  );
};

// Dashboard Stats Card
const StatsCard: React.FC<{ label: string; value: string | number; icon: React.ReactNode; trend?: 'up' | 'down' | 'neutral'; color?: string }> = ({
  label,
  value,
  icon,
  color = 'text-cyan-400',
}) => (
  <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
    <div className="flex items-center justify-between">
      <div className={`${color}`}>{icon}</div>
    </div>
    <div className="mt-2">
      <p className="text-2xl font-bold text-white">{value}</p>
      <p className="text-sm text-slate-400">{label}</p>
    </div>
  </div>
);

// Monitor Form Modal
const MonitorFormModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: CreateAsmMonitorRequest) => void;
  isLoading: boolean;
}> = ({ isOpen, onClose, onSubmit, isLoading }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    domains: '',
    schedule: '0 0 * * *', // Daily at midnight
    enableSubdomain: true,
    enablePortScan: true,
    enableServiceDetection: true,
    enableSslAnalysis: true,
    alertNewSubdomain: true,
    alertNewPort: true,
    alertCertChange: true,
    alertShadowIt: true,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const domains = formData.domains.split(',').map(d => d.trim()).filter(Boolean);
    if (domains.length === 0) {
      toast.error('Please enter at least one domain');
      return;
    }
    onSubmit({
      name: formData.name,
      description: formData.description || undefined,
      domains,
      schedule: formData.schedule,
      discovery_config: {
        enable_subdomain_enum: formData.enableSubdomain,
        enable_port_scan: formData.enablePortScan,
        enable_service_detection: formData.enableServiceDetection,
        enable_ssl_analysis: formData.enableSslAnalysis,
        enable_tech_detection: true,
        dns_resolvers: [],
      },
      alert_config: {
        alert_on_new_subdomain: formData.alertNewSubdomain,
        alert_on_new_port: formData.alertNewPort,
        alert_on_cert_change: formData.alertCertChange,
        alert_on_tech_change: true,
        alert_on_ip_change: true,
        alert_on_asset_removed: true,
        alert_on_shadow_it: formData.alertShadowIt,
        min_severity: 'low',
        notification_channels: [],
      },
    });
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-slate-800 rounded-lg border border-slate-700 p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Create ASM Monitor</h3>
          <button onClick={onClose} className="p-1 hover:bg-slate-700 rounded">
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="Production Assets Monitor"
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Description</label>
            <input
              type="text"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Monitor for production domain assets"
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Domains (comma-separated)</label>
            <input
              type="text"
              value={formData.domains}
              onChange={(e) => setFormData({ ...formData, domains: e.target.value })}
              placeholder="example.com, sub.example.com"
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Schedule (Cron)</label>
            <select
              value={formData.schedule}
              onChange={(e) => setFormData({ ...formData, schedule: e.target.value })}
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white"
            >
              <option value="0 * * * *">Hourly</option>
              <option value="0 */6 * * *">Every 6 hours</option>
              <option value="0 0 * * *">Daily</option>
              <option value="0 0 * * 0">Weekly</option>
            </select>
          </div>

          <div className="border-t border-slate-700 pt-4">
            <h4 className="text-sm font-medium text-slate-300 mb-2">Discovery Options</h4>
            <div className="grid grid-cols-2 gap-2">
              {[
                { key: 'enableSubdomain', label: 'Subdomain Enum' },
                { key: 'enablePortScan', label: 'Port Scanning' },
                { key: 'enableServiceDetection', label: 'Service Detection' },
                { key: 'enableSslAnalysis', label: 'SSL Analysis' },
              ].map((opt) => (
                <label key={opt.key} className="flex items-center gap-2 text-sm text-slate-300">
                  <input
                    type="checkbox"
                    checked={formData[opt.key as keyof typeof formData] as boolean}
                    onChange={(e) => setFormData({ ...formData, [opt.key]: e.target.checked })}
                    className="rounded bg-slate-700 border-slate-600 text-cyan-500"
                  />
                  {opt.label}
                </label>
              ))}
            </div>
          </div>

          <div className="border-t border-slate-700 pt-4">
            <h4 className="text-sm font-medium text-slate-300 mb-2">Alert Triggers</h4>
            <div className="grid grid-cols-2 gap-2">
              {[
                { key: 'alertNewSubdomain', label: 'New Subdomain' },
                { key: 'alertNewPort', label: 'New Port' },
                { key: 'alertCertChange', label: 'Cert Change' },
                { key: 'alertShadowIt', label: 'Shadow IT' },
              ].map((opt) => (
                <label key={opt.key} className="flex items-center gap-2 text-sm text-slate-300">
                  <input
                    type="checkbox"
                    checked={formData[opt.key as keyof typeof formData] as boolean}
                    onChange={(e) => setFormData({ ...formData, [opt.key]: e.target.checked })}
                    className="rounded bg-slate-700 border-slate-600 text-cyan-500"
                  />
                  {opt.label}
                </label>
              ))}
            </div>
          </div>

          <div className="flex gap-2 pt-4">
            <Button type="submit" disabled={isLoading}>
              {isLoading ? <RefreshCw className="w-4 h-4 animate-spin mr-2" /> : <Plus className="w-4 h-4 mr-2" />}
              Create Monitor
            </Button>
            <Button type="button" variant="secondary" onClick={onClose}>
              Cancel
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Monitor Card
const MonitorCard: React.FC<{
  monitor: AsmMonitor;
  onRun: () => void;
  onToggle: () => void;
  onDelete: () => void;
  onSelect: () => void;
}> = ({ monitor, onRun, onToggle, onDelete, onSelect }) => (
  <div
    className="bg-slate-800 rounded-lg border border-slate-700 p-4 hover:border-slate-600 transition-colors cursor-pointer"
    onClick={onSelect}
  >
    <div className="flex items-start justify-between">
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-cyan-400" />
          <h4 className="text-white font-medium">{monitor.name}</h4>
          <span className={`px-2 py-0.5 text-xs rounded ${monitor.enabled ? 'bg-green-500/20 text-green-400' : 'bg-slate-600 text-slate-400'}`}>
            {monitor.enabled ? 'Active' : 'Disabled'}
          </span>
        </div>
        {monitor.description && (
          <p className="text-sm text-slate-400 mt-1">{monitor.description}</p>
        )}
        <div className="flex flex-wrap gap-1 mt-2">
          {monitor.domains.slice(0, 3).map((domain, i) => (
            <span key={i} className="px-2 py-0.5 text-xs bg-slate-700 text-slate-300 rounded">
              {domain}
            </span>
          ))}
          {monitor.domains.length > 3 && (
            <span className="px-2 py-0.5 text-xs bg-slate-700 text-slate-400 rounded">
              +{monitor.domains.length - 3} more
            </span>
          )}
        </div>
        <div className="flex items-center gap-4 mt-3 text-xs text-slate-400">
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {monitor.schedule}
          </span>
          {monitor.last_run_at && (
            <span>Last run: {new Date(monitor.last_run_at).toLocaleDateString()}</span>
          )}
          {monitor.next_run_at && (
            <span>Next: {new Date(monitor.next_run_at).toLocaleDateString()}</span>
          )}
        </div>
      </div>
      <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
        <button
          onClick={onRun}
          className="p-2 hover:bg-slate-700 rounded-lg"
          title="Run now"
        >
          <Play className="w-4 h-4 text-green-400" />
        </button>
        <button
          onClick={onToggle}
          className="p-2 hover:bg-slate-700 rounded-lg"
          title={monitor.enabled ? 'Disable' : 'Enable'}
        >
          {monitor.enabled ? (
            <Pause className="w-4 h-4 text-yellow-400" />
          ) : (
            <Play className="w-4 h-4 text-cyan-400" />
          )}
        </button>
        <button
          onClick={onDelete}
          className="p-2 hover:bg-slate-700 rounded-lg"
          title="Delete"
        >
          <Trash2 className="w-4 h-4 text-red-400" />
        </button>
        <ChevronRight className="w-5 h-5 text-slate-500" />
      </div>
    </div>
  </div>
);

// Change Card
const ChangeCard: React.FC<{
  change: AsmChange;
  onAcknowledge: () => void;
}> = ({ change, onAcknowledge }) => {
  const changeType = getChangeTypeDisplay(change.change_type);
  return (
    <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className={`px-2 py-0.5 text-xs rounded border ${getSeverityColor(change.severity)}`}>
              {change.severity}
            </span>
            <span className={`text-sm font-medium ${changeType.color}`}>
              {changeType.label}
            </span>
          </div>
          <p className="text-white text-sm mt-1">{change.hostname}</p>
          <p className="text-xs text-slate-400 mt-1">{change.details.description}</p>
          <p className="text-xs text-slate-500 mt-1">
            {new Date(change.detected_at).toLocaleString()}
          </p>
        </div>
        {!change.acknowledged && (
          <button
            onClick={onAcknowledge}
            className="p-1.5 hover:bg-slate-700 rounded"
            title="Acknowledge"
          >
            <CheckCircle className="w-4 h-4 text-green-400" />
          </button>
        )}
        {change.acknowledged && (
          <span className="text-xs text-slate-500">Acknowledged</span>
        )}
      </div>
    </div>
  );
};

// Timeline Component
const Timeline: React.FC<{ events: AsmTimelineEvent[] }> = ({ events }) => (
  <div className="space-y-3">
    {events.map((event, index) => (
      <div key={index} className="flex gap-3">
        <div className="flex flex-col items-center">
          <div className={`w-2 h-2 rounded-full ${
            event.severity === 'critical' ? 'bg-red-400' :
            event.severity === 'high' ? 'bg-orange-400' :
            event.severity === 'medium' ? 'bg-yellow-400' :
            'bg-slate-500'
          }`} />
          {index < events.length - 1 && (
            <div className="w-px flex-1 bg-slate-700 mt-1" />
          )}
        </div>
        <div className="flex-1 pb-3">
          <p className="text-sm text-white">{event.description}</p>
          <p className="text-xs text-slate-400">
            {event.monitor_name} - {new Date(event.timestamp).toLocaleString()}
          </p>
        </div>
      </div>
    ))}
    {events.length === 0 && (
      <p className="text-slate-400 text-sm text-center py-4">No recent events</p>
    )}
  </div>
);

// Main Page Component
export default function AttackSurfacePage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedMonitorId, setSelectedMonitorId] = useState<string | null>(null);

  // Dashboard query
  const { data: dashboard } = useQuery({
    queryKey: ['asm-dashboard'],
    queryFn: async () => {
      const response = await asmAPI.getDashboard();
      return response.data;
    },
    refetchInterval: 30000,
  });

  // Monitors query
  const { data: monitors, isLoading: loadingMonitors } = useQuery({
    queryKey: ['asm-monitors'],
    queryFn: async () => {
      const response = await asmAPI.listMonitors();
      return response.data;
    },
  });

  // Changes query
  const { data: changes } = useQuery({
    queryKey: ['asm-changes'],
    queryFn: async () => {
      const response = await asmAPI.listChanges({ limit: 20, acknowledged: false });
      return response.data;
    },
    refetchInterval: 30000,
  });

  // Timeline query
  const { data: timeline } = useQuery({
    queryKey: ['asm-timeline'],
    queryFn: async () => {
      const response = await asmAPI.getTimeline(undefined, 7);
      return response.data;
    },
  });

  // Risk scores query
  const { data: riskScores } = useQuery({
    queryKey: ['asm-risk-scores'],
    queryFn: async () => {
      const response = await asmAPI.listRiskScores(10);
      return response.data;
    },
  });

  // Mutations
  const createMutation = useMutation({
    mutationFn: asmAPI.createMonitor,
    onSuccess: () => {
      toast.success('Monitor created successfully');
      queryClient.invalidateQueries({ queryKey: ['asm-monitors'] });
      queryClient.invalidateQueries({ queryKey: ['asm-dashboard'] });
      setShowCreateModal(false);
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      toast.error(err.response?.data?.error || 'Failed to create monitor');
    },
  });

  const runMutation = useMutation({
    mutationFn: asmAPI.runMonitor,
    onSuccess: (_, id) => {
      toast.success('Monitor scan started');
      queryClient.invalidateQueries({ queryKey: ['asm-monitors'] });
      queryClient.invalidateQueries({ queryKey: ['asm-timeline'] });
    },
    onError: () => toast.error('Failed to run monitor'),
  });

  const enableMutation = useMutation({
    mutationFn: asmAPI.enableMonitor,
    onSuccess: () => {
      toast.success('Monitor enabled');
      queryClient.invalidateQueries({ queryKey: ['asm-monitors'] });
      queryClient.invalidateQueries({ queryKey: ['asm-dashboard'] });
    },
    onError: () => toast.error('Failed to enable monitor'),
  });

  const disableMutation = useMutation({
    mutationFn: asmAPI.disableMonitor,
    onSuccess: () => {
      toast.success('Monitor disabled');
      queryClient.invalidateQueries({ queryKey: ['asm-monitors'] });
      queryClient.invalidateQueries({ queryKey: ['asm-dashboard'] });
    },
    onError: () => toast.error('Failed to disable monitor'),
  });

  const deleteMutation = useMutation({
    mutationFn: asmAPI.deleteMonitor,
    onSuccess: () => {
      toast.success('Monitor deleted');
      queryClient.invalidateQueries({ queryKey: ['asm-monitors'] });
      queryClient.invalidateQueries({ queryKey: ['asm-dashboard'] });
    },
    onError: () => toast.error('Failed to delete monitor'),
  });

  const acknowledgeMutation = useMutation({
    mutationFn: (changeId: string) => asmAPI.acknowledgeChange(changeId),
    onSuccess: () => {
      toast.success('Change acknowledged');
      queryClient.invalidateQueries({ queryKey: ['asm-changes'] });
      queryClient.invalidateQueries({ queryKey: ['asm-dashboard'] });
    },
    onError: () => toast.error('Failed to acknowledge change'),
  });

  return (
    <Layout>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Shield className="w-7 h-7 text-cyan-400" />
            Attack Surface Management
          </h1>
          <p className="text-slate-600 dark:text-slate-400 mt-1">
            Continuous external monitoring with change detection and risk scoring
          </p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus className="w-4 h-4 mr-2" />
          New Monitor
        </Button>
      </div>

      {/* Dashboard Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mb-6">
        <StatsCard
          label="Active Monitors"
          value={dashboard?.active_monitors || 0}
          icon={<Activity className="w-5 h-5" />}
        />
        <StatsCard
          label="Total Assets"
          value={dashboard?.total_assets || 0}
          icon={<Server className="w-5 h-5" />}
          color="text-green-400"
        />
        <StatsCard
          label="Changes (24h)"
          value={dashboard?.total_changes_24h || 0}
          icon={<TrendingUp className="w-5 h-5" />}
          color="text-yellow-400"
        />
        <StatsCard
          label="Unacknowledged"
          value={dashboard?.unacknowledged_changes || 0}
          icon={<AlertTriangle className="w-5 h-5" />}
          color="text-orange-400"
        />
        <StatsCard
          label="High Risk Assets"
          value={dashboard?.high_risk_assets || 0}
          icon={<AlertCircle className="w-5 h-5" />}
          color="text-red-400"
        />
        <StatsCard
          label="Shadow IT"
          value={dashboard?.shadow_it_count || 0}
          icon={<EyeOff className="w-5 h-5" />}
          color="text-purple-400"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Monitors */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-slate-800 rounded-lg border border-slate-700">
            <div className="p-4 border-b border-slate-700 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Globe className="w-5 h-5 text-cyan-400" />
                Monitors
              </h3>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => queryClient.invalidateQueries({ queryKey: ['asm-monitors'] })}
              >
                <RefreshCw className="w-4 h-4" />
              </Button>
            </div>
            <div className="p-4 space-y-3">
              {loadingMonitors ? (
                <div className="flex items-center justify-center py-8">
                  <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin" />
                </div>
              ) : monitors && monitors.length > 0 ? (
                monitors.map((monitor) => (
                  <MonitorCard
                    key={monitor.id}
                    monitor={monitor}
                    onRun={() => runMutation.mutate(monitor.id)}
                    onToggle={() =>
                      monitor.enabled
                        ? disableMutation.mutate(monitor.id)
                        : enableMutation.mutate(monitor.id)
                    }
                    onDelete={() => {
                      if (confirm('Delete this monitor?')) {
                        deleteMutation.mutate(monitor.id);
                      }
                    }}
                    onSelect={() => setSelectedMonitorId(monitor.id)}
                  />
                ))
              ) : (
                <div className="text-center py-8">
                  <Globe className="w-12 h-12 text-slate-600 mx-auto mb-3" />
                  <p className="text-slate-400">No monitors configured</p>
                  <p className="text-sm text-slate-500 mt-1">
                    Create a monitor to start tracking your attack surface
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Recent Changes */}
          <div className="bg-slate-800 rounded-lg border border-slate-700">
            <div className="p-4 border-b border-slate-700">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-orange-400" />
                Recent Changes
              </h3>
            </div>
            <div className="p-4 space-y-2 max-h-80 overflow-y-auto">
              {changes && changes.length > 0 ? (
                changes.map((change) => (
                  <ChangeCard
                    key={change.id}
                    change={change}
                    onAcknowledge={() => acknowledgeMutation.mutate(change.id)}
                  />
                ))
              ) : (
                <p className="text-slate-400 text-sm text-center py-4">
                  No unacknowledged changes
                </p>
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Timeline & Risk Scores */}
        <div className="space-y-4">
          {/* Timeline */}
          <div className="bg-slate-800 rounded-lg border border-slate-700">
            <div className="p-4 border-b border-slate-700">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Calendar className="w-5 h-5 text-cyan-400" />
                Activity Timeline
              </h3>
            </div>
            <div className="p-4 max-h-64 overflow-y-auto">
              <Timeline events={timeline || []} />
            </div>
          </div>

          {/* Risk Scores */}
          <div className="bg-slate-800 rounded-lg border border-slate-700">
            <div className="p-4 border-b border-slate-700">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <BarChart3 className="w-5 h-5 text-red-400" />
                Highest Risk Assets
              </h3>
            </div>
            <div className="p-4 space-y-3">
              {riskScores && riskScores.length > 0 ? (
                riskScores.slice(0, 5).map((score) => (
                  <div
                    key={score.id}
                    className="flex items-center justify-between bg-slate-700/50 rounded-lg p-3"
                  >
                    <div className="flex-1 min-w-0">
                      <p className="text-white text-sm font-medium truncate">
                        {score.hostname}
                      </p>
                      <p className="text-xs text-slate-400">
                        {score.factors.length} risk factors
                      </p>
                    </div>
                    <RiskScoreGauge score={score.overall_score} size="sm" />
                  </div>
                ))
              ) : (
                <p className="text-slate-400 text-sm text-center py-4">
                  No risk scores calculated yet
                </p>
              )}
            </div>
          </div>

          {/* Average Risk Score */}
          {dashboard && (
            <div className="bg-slate-800 rounded-lg border border-slate-700 p-6 text-center">
              <p className="text-sm text-slate-400 mb-2">Average Risk Score</p>
              <RiskScoreGauge score={Math.round(dashboard.average_risk_score)} size="lg" />
              <p className="text-xs text-slate-500 mt-3">
                Based on {dashboard.total_assets} monitored assets
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Create Monitor Modal */}
      <MonitorFormModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onSubmit={(data) => createMutation.mutate(data)}
        isLoading={createMutation.isPending}
      />
    </Layout>
  );
}
