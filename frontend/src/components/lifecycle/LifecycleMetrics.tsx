import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import {
  findingLifecycleAPI,
  type LifecycleMetrics as LifecycleMetricsType,
  type FindingLifecycle,
  type FindingState,
  type SlaPolicy,
} from '../../services/api';
import {
  AlertTriangle,
  Clock,
  CheckCircle,
  TrendingUp,
  BarChart3,
  AlertCircle,
  Timer,
  Plus,
  RefreshCw,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';

interface LifecycleMetricsProps {
  onFindingClick?: (findingId: string) => void;
}

const stateColors: Record<FindingState, string> = {
  discovered: '#6B7280',
  triaged: '#3B82F6',
  acknowledged: '#8B5CF6',
  in_remediation: '#F59E0B',
  verification_pending: '#F97316',
  verified: '#06B6D4',
  closed: '#10B981',
};

const severityColors: Record<string, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#3B82F6',
  info: '#6B7280',
};

const LifecycleMetrics: React.FC<LifecycleMetricsProps> = ({ onFindingClick }) => {
  const [metrics, setMetrics] = useState<LifecycleMetricsType | null>(null);
  const [breachedFindings, setBreachedFindings] = useState<FindingLifecycle[]>([]);
  const [slaPolicies, setSlaPolicies] = useState<SlaPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreatePolicyModal, setShowCreatePolicyModal] = useState(false);
  const [newPolicy, setNewPolicy] = useState({
    name: '',
    description: '',
    critical_hours: 24,
    high_hours: 72,
    medium_hours: 168,
    low_hours: 720,
    info_hours: 0,
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [metricsRes, breachedRes, policiesRes] = await Promise.all([
        findingLifecycleAPI.getMetrics(),
        findingLifecycleAPI.getSlaBreached(),
        findingLifecycleAPI.listSlaPolicies(),
      ]);
      setMetrics(metricsRes.data);
      setBreachedFindings(breachedRes.data.lifecycles);
      setSlaPolicies(policiesRes.data.policies);
    } catch (error) {
      console.error('Failed to load metrics:', error);
      toast.error('Failed to load lifecycle metrics');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateSlaStatus = async () => {
    try {
      const result = await findingLifecycleAPI.updateSlaStatus();
      toast.success(`Updated SLA status for ${result.data.updated_count} findings`);
      await loadData();
    } catch (error) {
      console.error('Failed to update SLA status:', error);
      toast.error('Failed to update SLA status');
    }
  };

  const handleCreatePolicy = async () => {
    try {
      await findingLifecycleAPI.createSlaPolicy(newPolicy);
      toast.success('SLA policy created');
      setShowCreatePolicyModal(false);
      setNewPolicy({
        name: '',
        description: '',
        critical_hours: 24,
        high_hours: 72,
        medium_hours: 168,
        low_hours: 720,
        info_hours: 0,
      });
      await loadData();
    } catch (error) {
      console.error('Failed to create policy:', error);
      toast.error('Failed to create SLA policy');
    }
  };

  const formatHours = (hours: number | null): string => {
    if (hours === null) return 'N/A';
    if (hours < 24) return `${hours}h`;
    const days = Math.floor(hours / 24);
    return `${days}d`;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (!metrics) {
    return (
      <div className="text-center text-gray-400 py-8">
        No metrics data available
      </div>
    );
  }

  // Prepare chart data
  const stateChartData = Object.entries(metrics.by_state || {}).map(([state, count]) => ({
    name: state.replace('_', ' ').replace(/\b\w/g, (l) => l.toUpperCase()),
    value: count,
    color: stateColors[state as FindingState] || '#6B7280',
  }));

  const severityChartData = Object.entries(metrics.by_severity || {}).map(([severity, count]) => ({
    name: severity.charAt(0).toUpperCase() + severity.slice(1),
    value: count,
    color: severityColors[severity.toLowerCase()] || '#6B7280',
  }));

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-900/30 rounded-lg">
              <BarChart3 className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-sm text-gray-400">Total Findings</p>
              <p className="text-2xl font-bold">{metrics.total_findings}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-900/30 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-sm text-gray-400">SLA Breached</p>
              <p className="text-2xl font-bold text-red-400">{metrics.sla_breached_count}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-900/30 rounded-lg">
              <Timer className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-sm text-gray-400">Avg. Time to Close</p>
              <p className="text-2xl font-bold">
                {metrics.average_time_to_close_hours
                  ? formatHours(metrics.average_time_to_close_hours)
                  : 'N/A'}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-900/30 rounded-lg">
              <TrendingUp className="w-5 h-5 text-yellow-400" />
            </div>
            <div>
              <p className="text-sm text-gray-400">Avg. Time to Remediate</p>
              <p className="text-2xl font-bold">
                {metrics.average_time_to_remediation_hours
                  ? formatHours(metrics.average_time_to_remediation_hours)
                  : 'N/A'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* State Distribution */}
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <h3 className="text-lg font-semibold mb-4">Findings by State</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={stateChartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {stateChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151' }}
                  labelStyle={{ color: '#E5E7EB' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <h3 className="text-lg font-semibold mb-4">Findings by Severity</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityChartData} layout="vertical">
                <XAxis type="number" stroke="#9CA3AF" />
                <YAxis type="category" dataKey="name" stroke="#9CA3AF" width={80} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151' }}
                  labelStyle={{ color: '#E5E7EB' }}
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {severityChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* SLA Breached Findings */}
      {breachedFindings.length > 0 && (
        <div className="bg-gray-800 rounded-lg p-4 border border-red-700">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h3 className="text-lg font-semibold text-red-400">SLA Breached Findings</h3>
            </div>
            <button
              onClick={handleUpdateSlaStatus}
              className="flex items-center gap-1 px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 rounded"
            >
              <RefreshCw className="w-4 h-4" />
              Update SLA Status
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-2 text-gray-400 font-medium">Title</th>
                  <th className="text-left py-2 text-gray-400 font-medium">Severity</th>
                  <th className="text-left py-2 text-gray-400 font-medium">State</th>
                  <th className="text-left py-2 text-gray-400 font-medium">SLA Due</th>
                  <th className="text-left py-2 text-gray-400 font-medium">Asset</th>
                </tr>
              </thead>
              <tbody>
                {breachedFindings.slice(0, 10).map((finding) => (
                  <tr
                    key={finding.id}
                    onClick={() => onFindingClick?.(finding.finding_id)}
                    className="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer"
                  >
                    <td className="py-2 text-gray-200">{finding.title}</td>
                    <td className="py-2">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-medium ${
                          finding.severity.toLowerCase() === 'critical'
                            ? 'bg-red-500/20 text-red-400'
                            : finding.severity.toLowerCase() === 'high'
                            ? 'bg-orange-500/20 text-orange-400'
                            : finding.severity.toLowerCase() === 'medium'
                            ? 'bg-yellow-500/20 text-yellow-400'
                            : 'bg-blue-500/20 text-blue-400'
                        }`}
                      >
                        {finding.severity}
                      </span>
                    </td>
                    <td className="py-2 text-gray-400">{finding.current_state.replace('_', ' ')}</td>
                    <td className="py-2 text-red-400">
                      {finding.sla_due_at
                        ? new Date(finding.sla_due_at).toLocaleDateString()
                        : 'N/A'}
                    </td>
                    <td className="py-2 text-gray-400">{finding.affected_asset}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {breachedFindings.length > 10 && (
            <p className="text-sm text-gray-400 mt-2">
              Showing 10 of {breachedFindings.length} breached findings
            </p>
          )}
        </div>
      )}

      {/* SLA Policies */}
      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">SLA Policies</h3>
          <button
            onClick={() => setShowCreatePolicyModal(true)}
            className="flex items-center gap-1 px-3 py-1 text-sm bg-cyan-600 hover:bg-cyan-500 rounded"
          >
            <Plus className="w-4 h-4" />
            Create Policy
          </button>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {slaPolicies.map((policy) => (
            <div
              key={policy.id}
              className={`p-4 rounded-lg border ${
                policy.is_default ? 'border-cyan-600 bg-cyan-900/10' : 'border-gray-700 bg-gray-700/30'
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                <h4 className="font-medium">{policy.name}</h4>
                {policy.is_default && (
                  <span className="text-xs bg-cyan-600 px-2 py-0.5 rounded">Default</span>
                )}
              </div>
              {policy.description && (
                <p className="text-sm text-gray-400 mb-3">{policy.description}</p>
              )}
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-red-400">Critical:</span>
                  <span>{formatHours(policy.critical_hours)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-orange-400">High:</span>
                  <span>{formatHours(policy.high_hours)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-yellow-400">Medium:</span>
                  <span>{formatHours(policy.medium_hours)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-blue-400">Low:</span>
                  <span>{formatHours(policy.low_hours)}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Create Policy Modal */}
      {showCreatePolicyModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold mb-4">Create SLA Policy</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Policy Name</label>
                <input
                  type="text"
                  value={newPolicy.name}
                  onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                  placeholder="e.g., Urgent Response Policy"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Description</label>
                <input
                  type="text"
                  value={newPolicy.description}
                  onChange={(e) => setNewPolicy({ ...newPolicy, description: e.target.value })}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                  placeholder="Optional description"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Critical (hours)</label>
                  <input
                    type="number"
                    value={newPolicy.critical_hours}
                    onChange={(e) =>
                      setNewPolicy({ ...newPolicy, critical_hours: parseInt(e.target.value) || 0 })
                    }
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">High (hours)</label>
                  <input
                    type="number"
                    value={newPolicy.high_hours}
                    onChange={(e) =>
                      setNewPolicy({ ...newPolicy, high_hours: parseInt(e.target.value) || 0 })
                    }
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Medium (hours)</label>
                  <input
                    type="number"
                    value={newPolicy.medium_hours}
                    onChange={(e) =>
                      setNewPolicy({ ...newPolicy, medium_hours: parseInt(e.target.value) || 0 })
                    }
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Low (hours)</label>
                  <input
                    type="number"
                    value={newPolicy.low_hours}
                    onChange={(e) =>
                      setNewPolicy({ ...newPolicy, low_hours: parseInt(e.target.value) || 0 })
                    }
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                  />
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowCreatePolicyModal(false)}
                className="px-4 py-2 text-sm bg-gray-700 hover:bg-gray-600 rounded"
              >
                Cancel
              </button>
              <button
                onClick={handleCreatePolicy}
                disabled={!newPolicy.name}
                className="px-4 py-2 text-sm bg-cyan-600 hover:bg-cyan-500 rounded disabled:opacity-50"
              >
                Create
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LifecycleMetrics;
