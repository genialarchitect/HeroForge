import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Users,
  Activity,
  AlertTriangle,
  Shield,
  Server,
  Plus,
  RefreshCw,
  Trash2,
  Edit,
  Eye,
  CheckCircle,
  XCircle,
  Clock,
  MapPin,
  Filter,
  Search,
  ChevronDown,
  X,
  UserCheck,
  UserX,
  TrendingUp,
  TrendingDown,
  Zap,
  Brain,
  Globe,
  Radar,
  Plane,
  Building2,
  Database,
  Network,
  Upload,
  Play,
  Settings2,
  ShieldAlert,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { Layout } from '../components/layout/Layout';
import { Button } from '../components/ui/Button';
import { uebaAPI } from '../services/api';
import type {
  UebaEntity,
  UebaAnomaly,
  UebaActivity,
  UebaPeerGroup,
  UebaSession,
  UebaBaseline,
  UebaDashboardStats,
  CreateUebaEntityRequest,
  UpdateUebaEntityRequest,
  CreateUebaPeerGroupRequest,
  UebaRiskFactor,
  UebaAdvancedStats,
  UebaAdvancedDetection,
  UebaBusinessHours,
  UebaSensitiveResource,
  UebaKnownVpn,
  UebaDetectionRule,
  UebaDataAccess,
  UebaHostAccess,
  UebaDataTransfer,
  CreateBusinessHoursRequest,
  CreateSensitiveResourceRequest,
  CreateKnownVpnRequest,
  CreateDetectionRuleRequest,
  UebaAdvancedDetectionType,
} from '../types';

type TabType = 'dashboard' | 'entities' | 'anomalies' | 'activities' | 'sessions' | 'peer-groups' | 'advanced';

const riskLevelColors: Record<string, { bg: string; text: string; border: string }> = {
  low: { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500' },
  critical: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500' },
};

const anomalyStatusColors: Record<string, { bg: string; text: string }> = {
  new: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  acknowledged: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  investigating: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  confirmed: { bg: 'bg-red-500/20', text: 'text-red-400' },
  false_positive: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  resolved: { bg: 'bg-green-500/20', text: 'text-green-400' },
  suppressed: { bg: 'bg-gray-600/20', text: 'text-gray-500' },
};

const entityTypeIcons: Record<string, React.ReactNode> = {
  user: <Users className="w-4 h-4" />,
  host: <Server className="w-4 h-4" />,
  service_account: <UserCheck className="w-4 h-4" />,
  application: <Zap className="w-4 h-4" />,
  device: <Server className="w-4 h-4" />,
  ip_address: <Globe className="w-4 h-4" />,
};

// Modal component
const Modal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  size?: 'md' | 'lg' | 'xl';
}> = ({ isOpen, onClose, title, children, size = 'lg' }) => {
  if (!isOpen) return null;

  const sizeClasses = {
    md: 'max-w-md',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className={`relative bg-gray-800 border border-gray-700 rounded-lg shadow-xl w-full ${sizeClasses[size]} max-h-[90vh] overflow-y-auto`}>
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <button
            onClick={onClose}
            className="p-1 rounded-lg hover:bg-gray-700 text-gray-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
};

// Dashboard Tab Component
const DashboardTab: React.FC = () => {
  const { data: dashboard, isLoading } = useQuery({
    queryKey: ['ueba', 'dashboard'],
    queryFn: async () => {
      const response = await uebaAPI.getDashboard();
      return response.data;
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-500" />
      </div>
    );
  }

  if (!dashboard) {
    return (
      <div className="text-center py-12 text-gray-400">
        <Brain className="w-16 h-16 mx-auto mb-4 opacity-50" />
        <p>No UEBA data available. Start by adding entities.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/20 rounded-lg">
              <Users className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Total Entities</p>
              <p className="text-2xl font-bold text-white">{dashboard.total_entities}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-500/20 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">High Risk Entities</p>
              <p className="text-2xl font-bold text-white">{dashboard.high_risk_entities}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-500/20 rounded-lg">
              <Shield className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Critical Risk</p>
              <p className="text-2xl font-bold text-white">{dashboard.critical_risk_entities}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/20 rounded-lg">
              <Activity className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">New Anomalies</p>
              <p className="text-2xl font-bold text-white">{dashboard.new_anomalies}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Risk Distribution & Anomaly Types */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <h3 className="text-lg font-medium text-white mb-4">Risk Distribution</h3>
          <div className="space-y-3">
            {Object.entries(dashboard.risk_distribution).map(([level, count]) => {
              const total = Object.values(dashboard.risk_distribution).reduce((a, b) => a + b, 0);
              const percentage = total > 0 ? (count / total) * 100 : 0;
              const colors = riskLevelColors[level] || riskLevelColors.low;
              return (
                <div key={level}>
                  <div className="flex justify-between text-sm mb-1">
                    <span className={`capitalize ${colors.text}`}>{level}</span>
                    <span className="text-gray-400">{count}</span>
                  </div>
                  <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${colors.bg} transition-all`}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <h3 className="text-lg font-medium text-white mb-4">Anomalies by Type</h3>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {dashboard.anomalies_by_type.length > 0 ? (
              dashboard.anomalies_by_type.map((item) => (
                <div key={item.anomaly_type} className="flex justify-between items-center py-1">
                  <span className="text-gray-300 text-sm capitalize">
                    {item.anomaly_type.replace(/_/g, ' ')}
                  </span>
                  <span className="text-cyan-400 font-medium">{item.count}</span>
                </div>
              ))
            ) : (
              <p className="text-gray-500 text-sm">No anomalies detected</p>
            )}
          </div>
        </div>
      </div>

      {/* Top Risk Entities & Recent Anomalies */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <h3 className="text-lg font-medium text-white mb-4">Top Risk Entities</h3>
          <div className="space-y-2">
            {dashboard.top_risk_entities.length > 0 ? (
              dashboard.top_risk_entities.slice(0, 5).map((entity) => {
                const colors = riskLevelColors[entity.risk_level] || riskLevelColors.low;
                return (
                  <div key={entity.entity_id} className="flex items-center justify-between py-2 border-b border-gray-700 last:border-0">
                    <div className="flex items-center gap-2">
                      <div className={`p-1 rounded ${colors.bg}`}>
                        {entityTypeIcons[entity.entity_type] || <Users className="w-4 h-4" />}
                      </div>
                      <div>
                        <p className="text-white text-sm font-medium">{entity.display_name || entity.entity_id}</p>
                        <p className="text-gray-500 text-xs capitalize">{entity.entity_type}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-1 text-xs rounded ${colors.bg} ${colors.text}`}>
                        Score: {entity.risk_score}
                      </span>
                    </div>
                  </div>
                );
              })
            ) : (
              <p className="text-gray-500 text-sm">No high-risk entities</p>
            )}
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <h3 className="text-lg font-medium text-white mb-4">Recent Anomalies</h3>
          <div className="space-y-2">
            {dashboard.recent_anomalies.length > 0 ? (
              dashboard.recent_anomalies.slice(0, 5).map((anomaly) => {
                const statusColors = anomalyStatusColors[anomaly.status] || anomalyStatusColors.new;
                return (
                  <div key={anomaly.id} className="py-2 border-b border-gray-700 last:border-0">
                    <div className="flex items-center justify-between">
                      <p className="text-white text-sm font-medium">{anomaly.title}</p>
                      <span className={`px-2 py-1 text-xs rounded ${statusColors.bg} ${statusColors.text}`}>
                        {anomaly.status}
                      </span>
                    </div>
                    <p className="text-gray-500 text-xs mt-1 capitalize">
                      {anomaly.anomaly_type.replace(/_/g, ' ')} • {new Date(anomaly.detected_at).toLocaleString()}
                    </p>
                  </div>
                );
              })
            ) : (
              <p className="text-gray-500 text-sm">No recent anomalies</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Entities Tab Component
const EntitiesTab: React.FC = () => {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [entityTypeFilter, setEntityTypeFilter] = useState<string>('');
  const [riskLevelFilter, setRiskLevelFilter] = useState<string>('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedEntity, setSelectedEntity] = useState<UebaEntity | null>(null);

  const { data: entitiesData, isLoading } = useQuery({
    queryKey: ['ueba', 'entities', { search, entityTypeFilter, riskLevelFilter }],
    queryFn: async () => {
      const response = await uebaAPI.listEntities({
        search: search || undefined,
        entity_type: entityTypeFilter || undefined,
        risk_level: riskLevelFilter || undefined,
        limit: 50,
      });
      return response.data;
    },
  });

  const createMutation = useMutation({
    mutationFn: (data: CreateUebaEntityRequest) => uebaAPI.createEntity(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'entities'] });
      toast.success('Entity created successfully');
      setShowCreateModal(false);
    },
    onError: () => toast.error('Failed to create entity'),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => uebaAPI.deleteEntity(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'entities'] });
      toast.success('Entity deleted successfully');
    },
    onError: () => toast.error('Failed to delete entity'),
  });

  const entities = entitiesData?.entities || [];

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search entities..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          />
        </div>
        <select
          value={entityTypeFilter}
          onChange={(e) => setEntityTypeFilter(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
        >
          <option value="">All Types</option>
          <option value="user">User</option>
          <option value="host">Host</option>
          <option value="service_account">Service Account</option>
          <option value="application">Application</option>
        </select>
        <select
          value={riskLevelFilter}
          onChange={(e) => setRiskLevelFilter(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
        >
          <option value="">All Risk Levels</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus className="w-4 h-4 mr-2" /> Add Entity
        </Button>
      </div>

      {/* Entities Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Entity</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Type</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Department</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Risk Score</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Status</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Last Activity</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-400">
                  <RefreshCw className="w-6 h-6 animate-spin mx-auto" />
                </td>
              </tr>
            ) : entities.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-400">
                  No entities found
                </td>
              </tr>
            ) : (
              entities.map((entity) => {
                const colors = riskLevelColors[entity.risk_level] || riskLevelColors.low;
                return (
                  <tr key={entity.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {entityTypeIcons[entity.entity_type] || <Users className="w-4 h-4 text-gray-400" />}
                        <div>
                          <p className="text-white font-medium">{entity.display_name || entity.entity_id}</p>
                          <p className="text-gray-500 text-sm">{entity.entity_id}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-gray-300 capitalize">{entity.entity_type.replace(/_/g, ' ')}</td>
                    <td className="px-4 py-3 text-gray-300">{entity.department || '-'}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-xs rounded ${colors.bg} ${colors.text}`}>
                        {entity.risk_score} ({entity.risk_level})
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-xs rounded ${entity.is_active ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>
                        {entity.is_active ? 'Active' : 'Inactive'}
                      </span>
                      {entity.is_privileged && (
                        <span className="ml-2 px-2 py-1 text-xs rounded bg-purple-500/20 text-purple-400">
                          Privileged
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-sm">
                      {entity.last_activity_at ? new Date(entity.last_activity_at).toLocaleString() : 'Never'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setSelectedEntity(entity)}
                          className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-white"
                          title="View details"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => deleteMutation.mutate(entity.id)}
                          className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-red-400"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Create Entity Modal */}
      <Modal isOpen={showCreateModal} onClose={() => setShowCreateModal(false)} title="Add Entity">
        <EntityForm
          onSubmit={(data) => createMutation.mutate(data)}
          onCancel={() => setShowCreateModal(false)}
          loading={createMutation.isPending}
        />
      </Modal>

      {/* Entity Detail Modal */}
      {selectedEntity && (
        <Modal isOpen={true} onClose={() => setSelectedEntity(null)} title="Entity Details" size="xl">
          <EntityDetail entity={selectedEntity} onClose={() => setSelectedEntity(null)} />
        </Modal>
      )}
    </div>
  );
};

// Entity Form Component
const EntityForm: React.FC<{
  onSubmit: (data: CreateUebaEntityRequest) => void;
  onCancel: () => void;
  loading?: boolean;
}> = ({ onSubmit, onCancel, loading }) => {
  const [formData, setFormData] = useState<CreateUebaEntityRequest>({
    entity_type: 'user',
    entity_id: '',
    display_name: '',
    department: '',
    role: '',
    location: '',
    is_privileged: false,
    is_service_account: false,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Entity Type *</label>
          <select
            required
            value={formData.entity_type}
            onChange={(e) => setFormData({ ...formData, entity_type: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
          >
            <option value="user">User</option>
            <option value="host">Host</option>
            <option value="service_account">Service Account</option>
            <option value="application">Application</option>
            <option value="device">Device</option>
            <option value="ip_address">IP Address</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Entity ID *</label>
          <input
            type="text"
            required
            value={formData.entity_id}
            onChange={(e) => setFormData({ ...formData, entity_id: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
            placeholder="e.g., john.doe@example.com"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Display Name</label>
        <input
          type="text"
          value={formData.display_name || ''}
          onChange={(e) => setFormData({ ...formData, display_name: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
          placeholder="e.g., John Doe"
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Department</label>
          <input
            type="text"
            value={formData.department || ''}
            onChange={(e) => setFormData({ ...formData, department: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
            placeholder="e.g., Engineering"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Role</label>
          <input
            type="text"
            value={formData.role || ''}
            onChange={(e) => setFormData({ ...formData, role: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
            placeholder="e.g., Developer"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Location</label>
          <input
            type="text"
            value={formData.location || ''}
            onChange={(e) => setFormData({ ...formData, location: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
            placeholder="e.g., New York"
          />
        </div>
      </div>

      <div className="flex gap-4">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.is_privileged}
            onChange={(e) => setFormData({ ...formData, is_privileged: e.target.checked })}
            className="rounded border-gray-700 bg-gray-900 text-cyan-500"
          />
          <span className="text-gray-300">Privileged Account</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.is_service_account}
            onChange={(e) => setFormData({ ...formData, is_service_account: e.target.checked })}
            className="rounded border-gray-700 bg-gray-900 text-cyan-500"
          />
          <span className="text-gray-300">Service Account</span>
        </label>
      </div>

      <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
        <Button variant="secondary" onClick={onCancel}>Cancel</Button>
        <Button type="submit" loading={loading}>Create Entity</Button>
      </div>
    </form>
  );
};

// Entity Detail Component
const EntityDetail: React.FC<{
  entity: UebaEntity;
  onClose: () => void;
}> = ({ entity }) => {
  const { data: baselines } = useQuery({
    queryKey: ['ueba', 'entity', entity.id, 'baselines'],
    queryFn: async () => {
      const response = await uebaAPI.getEntityBaselines(entity.id);
      return response.data;
    },
  });

  const { data: riskFactors } = useQuery({
    queryKey: ['ueba', 'entity', entity.id, 'riskFactors'],
    queryFn: async () => {
      const response = await uebaAPI.getEntityRiskFactors(entity.id);
      return response.data;
    },
  });

  const colors = riskLevelColors[entity.risk_level] || riskLevelColors.low;

  return (
    <div className="space-y-6">
      {/* Entity Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <div className={`p-3 rounded-lg ${colors.bg}`}>
            {entityTypeIcons[entity.entity_type] || <Users className="w-8 h-8" />}
          </div>
          <div>
            <h3 className="text-xl font-bold text-white">{entity.display_name || entity.entity_id}</h3>
            <p className="text-gray-400 capitalize">{entity.entity_type.replace(/_/g, ' ')}</p>
          </div>
        </div>
        <div className={`px-4 py-2 rounded-lg ${colors.bg} ${colors.text} font-bold`}>
          Risk Score: {entity.risk_score}
        </div>
      </div>

      {/* Entity Info Grid */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-900 rounded-lg p-3">
          <p className="text-gray-500 text-sm">Department</p>
          <p className="text-white">{entity.department || 'N/A'}</p>
        </div>
        <div className="bg-gray-900 rounded-lg p-3">
          <p className="text-gray-500 text-sm">Role</p>
          <p className="text-white">{entity.role || 'N/A'}</p>
        </div>
        <div className="bg-gray-900 rounded-lg p-3">
          <p className="text-gray-500 text-sm">Location</p>
          <p className="text-white">{entity.location || 'N/A'}</p>
        </div>
        <div className="bg-gray-900 rounded-lg p-3">
          <p className="text-gray-500 text-sm">Status</p>
          <p className={entity.is_active ? 'text-green-400' : 'text-gray-400'}>
            {entity.is_active ? 'Active' : 'Inactive'}
          </p>
        </div>
        <div className="bg-gray-900 rounded-lg p-3">
          <p className="text-gray-500 text-sm">First Seen</p>
          <p className="text-white">{entity.first_seen_at ? new Date(entity.first_seen_at).toLocaleDateString() : 'N/A'}</p>
        </div>
        <div className="bg-gray-900 rounded-lg p-3">
          <p className="text-gray-500 text-sm">Last Activity</p>
          <p className="text-white">{entity.last_activity_at ? new Date(entity.last_activity_at).toLocaleString() : 'Never'}</p>
        </div>
      </div>

      {/* Risk Factors */}
      <div>
        <h4 className="text-lg font-medium text-white mb-3">Risk Factors</h4>
        <div className="bg-gray-900 rounded-lg p-4">
          {riskFactors?.risk_factors && riskFactors.risk_factors.length > 0 ? (
            <div className="space-y-2">
              {riskFactors.risk_factors.map((factor: UebaRiskFactor) => (
                <div key={factor.id} className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0">
                  <div>
                    <p className="text-white capitalize">{factor.factor_type.replace(/_/g, ' ')}</p>
                    <p className="text-gray-500 text-sm">{factor.description}</p>
                  </div>
                  <span className="text-orange-400 font-medium">+{factor.contribution}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500">No risk factors contributing to score</p>
          )}
        </div>
      </div>

      {/* Baselines */}
      <div>
        <h4 className="text-lg font-medium text-white mb-3">Behavioral Baselines</h4>
        <div className="bg-gray-900 rounded-lg p-4">
          {baselines && baselines.length > 0 ? (
            <div className="space-y-2">
              {baselines.slice(0, 5).map((baseline: UebaBaseline) => (
                <div key={baseline.id} className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0">
                  <div>
                    <p className="text-white">{baseline.metric_name}</p>
                    <p className="text-gray-500 text-sm capitalize">{baseline.metric_category.replace(/_/g, ' ')}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-cyan-400">Mean: {baseline.mean_value?.toFixed(2) || 'N/A'}</p>
                    <p className="text-gray-500 text-sm">±{baseline.std_deviation?.toFixed(2) || 0}</p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500">No baselines established yet. Baselines are calculated after sufficient activity data.</p>
          )}
        </div>
      </div>
    </div>
  );
};

// Anomalies Tab Component
const AnomaliesTab: React.FC = () => {
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [selectedAnomaly, setSelectedAnomaly] = useState<UebaAnomaly | null>(null);

  const { data: anomaliesData, isLoading } = useQuery({
    queryKey: ['ueba', 'anomalies', { statusFilter, typeFilter }],
    queryFn: async () => {
      const response = await uebaAPI.listAnomalies({
        status: statusFilter || undefined,
        anomaly_type: typeFilter || undefined,
        limit: 50,
      });
      return response.data;
    },
  });

  const acknowledgeMutation = useMutation({
    mutationFn: (id: string) => uebaAPI.acknowledgeAnomaly(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'anomalies'] });
      toast.success('Anomaly acknowledged');
    },
    onError: () => toast.error('Failed to acknowledge anomaly'),
  });

  const resolveMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { resolution_notes?: string; false_positive?: boolean } }) =>
      uebaAPI.resolveAnomaly(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'anomalies'] });
      toast.success('Anomaly resolved');
    },
    onError: () => toast.error('Failed to resolve anomaly'),
  });

  const anomalies = anomaliesData?.anomalies || [];

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-4">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
        >
          <option value="">All Statuses</option>
          <option value="new">New</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="investigating">Investigating</option>
          <option value="confirmed">Confirmed</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
        >
          <option value="">All Types</option>
          <option value="impossible_travel">Impossible Travel</option>
          <option value="off_hours_activity">Off-Hours Activity</option>
          <option value="excessive_failed_logins">Excessive Failed Logins</option>
          <option value="baseline_deviation">Baseline Deviation</option>
          <option value="unusual_data_access">Unusual Data Access</option>
          <option value="lateral_movement">Lateral Movement</option>
        </select>
      </div>

      {/* Anomalies List */}
      <div className="space-y-3">
        {isLoading ? (
          <div className="flex justify-center py-8">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-500" />
          </div>
        ) : anomalies.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            <AlertTriangle className="w-12 h-12 mx-auto mb-3 opacity-50" />
            <p>No anomalies found</p>
          </div>
        ) : (
          anomalies.map((anomaly) => {
            const statusColor = anomalyStatusColors[anomaly.status] || anomalyStatusColors.new;
            const severityColor = riskLevelColors[anomaly.severity.toLowerCase()] || riskLevelColors.medium;
            return (
              <div
                key={anomaly.id}
                className={`bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-gray-600 cursor-pointer transition-colors ${severityColor.border} border-l-4`}
                onClick={() => setSelectedAnomaly(anomaly)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <AlertTriangle className={`w-4 h-4 ${severityColor.text}`} />
                      <h4 className="text-white font-medium">{anomaly.title}</h4>
                      <span className={`px-2 py-0.5 text-xs rounded ${statusColor.bg} ${statusColor.text}`}>
                        {anomaly.status.replace(/_/g, ' ')}
                      </span>
                    </div>
                    <p className="text-gray-400 text-sm mb-2">{anomaly.description}</p>
                    <div className="flex items-center gap-4 text-xs text-gray-500">
                      <span className="capitalize">{anomaly.anomaly_type.replace(/_/g, ' ')}</span>
                      <span>•</span>
                      <span>Detected: {new Date(anomaly.detected_at).toLocaleString()}</span>
                      <span>•</span>
                      <span>Impact: +{anomaly.risk_score_impact} risk</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 ml-4">
                    {anomaly.status === 'new' && (
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={(e) => {
                          e.stopPropagation();
                          acknowledgeMutation.mutate(anomaly.id);
                        }}
                      >
                        <CheckCircle className="w-4 h-4 mr-1" /> Ack
                      </Button>
                    )}
                    {anomaly.status !== 'resolved' && anomaly.status !== 'false_positive' && (
                      <Button
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          resolveMutation.mutate({ id: anomaly.id, data: {} });
                        }}
                      >
                        Resolve
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Anomaly Detail Modal */}
      {selectedAnomaly && (
        <Modal isOpen={true} onClose={() => setSelectedAnomaly(null)} title="Anomaly Details" size="xl">
          <div className="space-y-4">
            <div className="flex items-start gap-4">
              <div className={`p-3 rounded-lg ${riskLevelColors[selectedAnomaly.severity.toLowerCase()]?.bg || 'bg-orange-500/20'}`}>
                <AlertTriangle className="w-8 h-8 text-orange-400" />
              </div>
              <div className="flex-1">
                <h3 className="text-xl font-bold text-white">{selectedAnomaly.title}</h3>
                <p className="text-gray-400 mt-1">{selectedAnomaly.description}</p>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4">
              <div className="bg-gray-900 rounded-lg p-3">
                <p className="text-gray-500 text-sm">Type</p>
                <p className="text-white capitalize">{selectedAnomaly.anomaly_type.replace(/_/g, ' ')}</p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3">
                <p className="text-gray-500 text-sm">Severity</p>
                <p className={`capitalize ${riskLevelColors[selectedAnomaly.severity.toLowerCase()]?.text || 'text-white'}`}>
                  {selectedAnomaly.severity}
                </p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3">
                <p className="text-gray-500 text-sm">Risk Impact</p>
                <p className="text-orange-400">+{selectedAnomaly.risk_score_impact}</p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3">
                <p className="text-gray-500 text-sm">Confidence</p>
                <p className="text-white">{selectedAnomaly.confidence ? `${(selectedAnomaly.confidence * 100).toFixed(0)}%` : 'N/A'}</p>
              </div>
            </div>

            <div className="bg-gray-900 rounded-lg p-4">
              <h4 className="text-white font-medium mb-2">Evidence</h4>
              <pre className="text-gray-400 text-sm whitespace-pre-wrap overflow-auto max-h-48">
                {selectedAnomaly.evidence}
              </pre>
            </div>

            {selectedAnomaly.mitre_techniques && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-white font-medium mb-2">MITRE ATT&CK Techniques</h4>
                <div className="flex flex-wrap gap-2">
                  {JSON.parse(selectedAnomaly.mitre_techniques).map((technique: string) => (
                    <span key={technique} className="px-2 py-1 bg-purple-500/20 text-purple-400 text-sm rounded">
                      {technique}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
};

// Activities Tab Component (simplified)
const ActivitiesTab: React.FC = () => {
  const [entityFilter, setEntityFilter] = useState<string>('');
  const [anomalousOnly, setAnomalousOnly] = useState(false);

  const { data: activitiesData, isLoading } = useQuery({
    queryKey: ['ueba', 'activities', { entityFilter, anomalousOnly }],
    queryFn: async () => {
      const response = await uebaAPI.listActivities({
        entity_id: entityFilter || undefined,
        is_anomalous: anomalousOnly || undefined,
        limit: 50,
      });
      return response.data;
    },
  });

  const activities = activitiesData?.activities || [];

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-4">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={anomalousOnly}
            onChange={(e) => setAnomalousOnly(e.target.checked)}
            className="rounded border-gray-700 bg-gray-900 text-cyan-500"
          />
          <span className="text-gray-300">Anomalous Only</span>
        </label>
      </div>

      {/* Activities Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Activity</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Source</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Destination</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Risk</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-400">
                  <RefreshCw className="w-6 h-6 animate-spin mx-auto" />
                </td>
              </tr>
            ) : activities.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-400">
                  No activities found
                </td>
              </tr>
            ) : (
              activities.map((activity) => (
                <tr key={activity.id} className={`border-b border-gray-700 hover:bg-gray-700/50 ${activity.is_anomalous ? 'bg-orange-500/5' : ''}`}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Activity className={`w-4 h-4 ${activity.is_anomalous ? 'text-orange-400' : 'text-gray-400'}`} />
                      <span className="text-white capitalize">{activity.activity_type.replace(/_/g, ' ')}</span>
                      {activity.is_anomalous && (
                        <span className="px-2 py-0.5 text-xs rounded bg-orange-500/20 text-orange-400">Anomalous</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-300">
                    {activity.source_ip && (
                      <div>
                        <p>{activity.source_ip}</p>
                        {activity.source_country && <p className="text-gray-500 text-xs">{activity.source_country}</p>}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-300">{activity.destination || '-'}</td>
                  <td className="px-4 py-3">
                    <span className={`text-${activity.risk_contribution > 5 ? 'orange' : activity.risk_contribution > 0 ? 'yellow' : 'gray'}-400`}>
                      +{activity.risk_contribution}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-sm">{new Date(activity.timestamp).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// Sessions Tab Component (simplified)
const SessionsTab: React.FC = () => {
  const { data: sessionsData, isLoading } = useQuery({
    queryKey: ['ueba', 'sessions'],
    queryFn: async () => {
      const response = await uebaAPI.listSessions({ limit: 50 });
      return response.data;
    },
  });

  const sessions = sessionsData?.sessions || [];

  return (
    <div className="space-y-4">
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Session</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Source</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Auth</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Security</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Started</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-400">
                  <RefreshCw className="w-6 h-6 animate-spin mx-auto" />
                </td>
              </tr>
            ) : sessions.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-400">
                  No sessions found
                </td>
              </tr>
            ) : (
              sessions.map((session) => (
                <tr key={session.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                  <td className="px-4 py-3">
                    <span className="text-white capitalize">{session.session_type}</span>
                    {session.session_id && <p className="text-gray-500 text-xs">{session.session_id.slice(0, 20)}...</p>}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-gray-400" />
                      <div>
                        <p className="text-white">{session.source_ip}</p>
                        {session.source_country && (
                          <p className="text-gray-500 text-xs">{session.source_city}, {session.source_country}</p>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 text-xs rounded ${session.auth_status === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                      {session.auth_status}
                    </span>
                    {session.mfa_used && (
                      <span className="ml-2 px-2 py-1 text-xs rounded bg-blue-500/20 text-blue-400">MFA</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1">
                      {session.is_vpn && <span className="px-2 py-0.5 text-xs rounded bg-purple-500/20 text-purple-400">VPN</span>}
                      {session.is_tor && <span className="px-2 py-0.5 text-xs rounded bg-red-500/20 text-red-400">TOR</span>}
                      {session.is_proxy && <span className="px-2 py-0.5 text-xs rounded bg-yellow-500/20 text-yellow-400">Proxy</span>}
                      {!session.is_vpn && !session.is_tor && !session.is_proxy && <span className="text-gray-500">-</span>}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-sm">{new Date(session.started_at).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// Peer Groups Tab Component (simplified)
const PeerGroupsTab: React.FC = () => {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);

  const { data: peerGroupsData, isLoading } = useQuery({
    queryKey: ['ueba', 'peer-groups'],
    queryFn: async () => {
      const response = await uebaAPI.listPeerGroups();
      return response.data;
    },
  });

  const createMutation = useMutation({
    mutationFn: (data: CreateUebaPeerGroupRequest) => uebaAPI.createPeerGroup(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'peer-groups'] });
      toast.success('Peer group created successfully');
      setShowCreateModal(false);
    },
    onError: () => toast.error('Failed to create peer group'),
  });

  const peerGroups = peerGroupsData?.peer_groups || [];

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus className="w-4 h-4 mr-2" /> Create Peer Group
        </Button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {isLoading ? (
          <div className="col-span-2 flex justify-center py-8">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-500" />
          </div>
        ) : peerGroups.length === 0 ? (
          <div className="col-span-2 text-center py-8 text-gray-400">
            <Users className="w-12 h-12 mx-auto mb-3 opacity-50" />
            <p>No peer groups defined</p>
          </div>
        ) : (
          peerGroups.map((group) => (
            <div key={group.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="text-white font-medium">{group.name}</h4>
                  <p className="text-gray-400 text-sm mt-1">{group.description || 'No description'}</p>
                </div>
                <span className="px-2 py-1 bg-cyan-500/20 text-cyan-400 text-sm rounded">
                  {group.member_count} members
                </span>
              </div>
              {group.is_auto_generated && (
                <span className="mt-2 inline-block px-2 py-0.5 text-xs rounded bg-gray-700 text-gray-400">
                  Auto-generated
                </span>
              )}
            </div>
          ))
        )}
      </div>

      {/* Create Peer Group Modal */}
      <Modal isOpen={showCreateModal} onClose={() => setShowCreateModal(false)} title="Create Peer Group">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const form = e.target as HTMLFormElement;
            const formData = new FormData(form);
            createMutation.mutate({
              name: formData.get('name') as string,
              description: formData.get('description') as string || undefined,
              criteria: {
                department: formData.get('department') as string || undefined,
                role: formData.get('role') as string || undefined,
                entity_type: formData.get('entity_type') as string || undefined,
              },
            });
          }}
          className="space-y-4"
        >
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Name *</label>
            <input
              name="name"
              type="text"
              required
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
              placeholder="e.g., Engineering Team"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
            <textarea
              name="description"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
              rows={2}
              placeholder="Optional description"
            />
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Department</label>
              <input
                name="department"
                type="text"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
                placeholder="e.g., Engineering"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Role</label>
              <input
                name="role"
                type="text"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
                placeholder="e.g., Developer"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Entity Type</label>
              <select
                name="entity_type"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
              >
                <option value="">Any</option>
                <option value="user">User</option>
                <option value="host">Host</option>
                <option value="service_account">Service Account</option>
              </select>
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
            <Button variant="secondary" onClick={() => setShowCreateModal(false)}>Cancel</Button>
            <Button type="submit" loading={createMutation.isPending}>Create</Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

// Advanced Detection Tab Component (Sprint 4)
const AdvancedTab: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeSubTab, setActiveSubTab] = useState<'detections' | 'config' | 'data'>('detections');
  const [showBusinessHoursModal, setShowBusinessHoursModal] = useState(false);
  const [showSensitiveResourceModal, setShowSensitiveResourceModal] = useState(false);
  const [showKnownVpnModal, setShowKnownVpnModal] = useState(false);
  const [showDetectionRuleModal, setShowDetectionRuleModal] = useState(false);
  const [selectedDetection, setSelectedDetection] = useState<UebaAdvancedDetection | null>(null);

  // Fetch advanced stats
  const { data: advancedStats, isLoading: loadingStats } = useQuery({
    queryKey: ['ueba', 'advanced', 'stats'],
    queryFn: async () => {
      const response = await uebaAPI.getAdvancedStats();
      return response.data;
    },
  });

  // Fetch advanced detections
  const { data: detectionsData, isLoading: loadingDetections } = useQuery({
    queryKey: ['ueba', 'advanced', 'detections'],
    queryFn: async () => {
      const response = await uebaAPI.listAdvancedDetections({ limit: 50 });
      return response.data;
    },
  });

  // Fetch business hours
  const { data: businessHoursData } = useQuery({
    queryKey: ['ueba', 'advanced', 'business-hours'],
    queryFn: async () => {
      const response = await uebaAPI.listBusinessHours();
      return response.data;
    },
  });

  // Fetch sensitive resources
  const { data: sensitiveResourcesData } = useQuery({
    queryKey: ['ueba', 'advanced', 'sensitive-resources'],
    queryFn: async () => {
      const response = await uebaAPI.listSensitiveResources();
      return response.data;
    },
  });

  // Fetch known VPNs
  const { data: knownVpnsData } = useQuery({
    queryKey: ['ueba', 'advanced', 'known-vpns'],
    queryFn: async () => {
      const response = await uebaAPI.listKnownVpns();
      return response.data;
    },
  });

  // Fetch detection rules
  const { data: detectionRulesData } = useQuery({
    queryKey: ['ueba', 'advanced', 'detection-rules'],
    queryFn: async () => {
      const response = await uebaAPI.listDetectionRules();
      return response.data;
    },
  });

  // Run detection mutation
  const runDetectionMutation = useMutation({
    mutationFn: async (detectionType: string) => {
      return uebaAPI.runAdvancedDetection({ detection_type: detectionType as UebaAdvancedDetectionType, time_window_hours: 24 });
    },
    onSuccess: (response) => {
      const result = response.data;
      toast.success(`Detection complete: ${result.detections_created} detections found from ${result.entities_analyzed} entities`);
      queryClient.invalidateQueries({ queryKey: ['ueba', 'advanced'] });
    },
    onError: () => toast.error('Failed to run detection'),
  });

  // Create mutations
  const createBusinessHoursMutation = useMutation({
    mutationFn: (data: CreateBusinessHoursRequest) => uebaAPI.createBusinessHours(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'advanced', 'business-hours'] });
      toast.success('Business hours created');
      setShowBusinessHoursModal(false);
    },
    onError: () => toast.error('Failed to create business hours'),
  });

  const createSensitiveResourceMutation = useMutation({
    mutationFn: (data: CreateSensitiveResourceRequest) => uebaAPI.createSensitiveResource(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'advanced', 'sensitive-resources'] });
      toast.success('Sensitive resource created');
      setShowSensitiveResourceModal(false);
    },
    onError: () => toast.error('Failed to create sensitive resource'),
  });

  const createKnownVpnMutation = useMutation({
    mutationFn: (data: CreateKnownVpnRequest) => uebaAPI.createKnownVpn(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'advanced', 'known-vpns'] });
      toast.success('Known VPN created');
      setShowKnownVpnModal(false);
    },
    onError: () => toast.error('Failed to create known VPN'),
  });

  const createDetectionRuleMutation = useMutation({
    mutationFn: (data: CreateDetectionRuleRequest) => uebaAPI.createDetectionRule(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'advanced', 'detection-rules'] });
      toast.success('Detection rule created');
      setShowDetectionRuleModal(false);
    },
    onError: () => toast.error('Failed to create detection rule'),
  });

  // Delete mutations
  const deleteBusinessHoursMutation = useMutation({
    mutationFn: (id: string) => uebaAPI.deleteBusinessHours(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'advanced', 'business-hours'] });
      toast.success('Business hours deleted');
    },
    onError: () => toast.error('Failed to delete business hours'),
  });

  const deleteSensitiveResourceMutation = useMutation({
    mutationFn: (id: string) => uebaAPI.deleteSensitiveResource(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'advanced', 'sensitive-resources'] });
      toast.success('Sensitive resource deleted');
    },
    onError: () => toast.error('Failed to delete sensitive resource'),
  });

  const deleteKnownVpnMutation = useMutation({
    mutationFn: (id: string) => uebaAPI.deleteKnownVpn(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'advanced', 'known-vpns'] });
      toast.success('Known VPN deleted');
    },
    onError: () => toast.error('Failed to delete known VPN'),
  });

  const deleteDetectionRuleMutation = useMutation({
    mutationFn: (id: string) => uebaAPI.deleteDetectionRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ueba', 'advanced', 'detection-rules'] });
      toast.success('Detection rule deleted');
    },
    onError: () => toast.error('Failed to delete detection rule'),
  });

  const detections = detectionsData?.detections || [];
  const businessHours = businessHoursData || [];
  const sensitiveResources = sensitiveResourcesData || [];
  const knownVpns = knownVpnsData || [];
  const detectionRules = detectionRulesData || [];

  const detectionTypes = [
    { id: 'impossible_travel', label: 'Impossible Travel', icon: <Plane className="w-4 h-4" />, description: 'Detect logins from geographically distant locations in short time' },
    { id: 'unusual_data_access', label: 'Unusual Data Access', icon: <Database className="w-4 h-4" />, description: 'Detect access to sensitive data outside normal patterns' },
    { id: 'off_hours_activity', label: 'Off-Hours Activity', icon: <Clock className="w-4 h-4" />, description: 'Detect activity outside business hours' },
    { id: 'service_account_abuse', label: 'Service Account Abuse', icon: <UserCheck className="w-4 h-4" />, description: 'Detect misuse of service accounts' },
    { id: 'lateral_movement', label: 'Lateral Movement', icon: <Network className="w-4 h-4" />, description: 'Detect host-to-host movement patterns' },
    { id: 'data_exfiltration', label: 'Data Exfiltration', icon: <Upload className="w-4 h-4" />, description: 'Detect large data transfers to external destinations' },
  ];

  const sensitivityColors: Record<string, { bg: string; text: string }> = {
    public: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
    internal: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
    confidential: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
    restricted: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
    top_secret: { bg: 'bg-red-500/20', text: 'text-red-400' },
  };

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-5 gap-4">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/20 rounded-lg">
              <Radar className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Total Detections</p>
              <p className="text-2xl font-bold text-white">{advancedStats?.total_detections || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/20 rounded-lg">
              <Activity className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">New (24h)</p>
              <p className="text-2xl font-bold text-white">{advancedStats?.new_detections_24h || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-500/20 rounded-lg">
              <ShieldAlert className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Confirmed</p>
              <p className="text-2xl font-bold text-white">{advancedStats?.confirmed_detections || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/20 rounded-lg">
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">False Positives</p>
              <p className="text-2xl font-bold text-white">{advancedStats?.false_positives || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-500/20 rounded-lg">
              <Settings2 className="w-5 h-5 text-yellow-400" />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Active Rules</p>
              <p className="text-2xl font-bold text-white">{detectionRules.filter((r: UebaDetectionRule) => r.enabled).length}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Sub Tabs */}
      <div className="flex gap-4 border-b border-gray-700 pb-2">
        <button
          onClick={() => setActiveSubTab('detections')}
          className={`px-3 py-1 rounded-t-lg ${activeSubTab === 'detections' ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'}`}
        >
          Detections
        </button>
        <button
          onClick={() => setActiveSubTab('config')}
          className={`px-3 py-1 rounded-t-lg ${activeSubTab === 'config' ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'}`}
        >
          Configuration
        </button>
        <button
          onClick={() => setActiveSubTab('data')}
          className={`px-3 py-1 rounded-t-lg ${activeSubTab === 'data' ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'}`}
        >
          Run Detection
        </button>
      </div>

      {/* Detections Sub Tab */}
      {activeSubTab === 'detections' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-6">
            {/* Detections by Type */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <h3 className="text-lg font-medium text-white mb-4">Detections by Type</h3>
              <div className="space-y-2">
                {advancedStats?.detections_by_type?.length ? (
                  advancedStats.detections_by_type.map((item: { detection_type: string; count: number }) => (
                    <div key={item.detection_type} className="flex justify-between items-center py-1">
                      <span className="text-gray-300 text-sm capitalize">{item.detection_type.replace(/_/g, ' ')}</span>
                      <span className="text-cyan-400 font-medium">{item.count}</span>
                    </div>
                  ))
                ) : (
                  <p className="text-gray-500 text-sm">No detections yet</p>
                )}
              </div>
            </div>

            {/* Detections by Severity */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <h3 className="text-lg font-medium text-white mb-4">Detections by Severity</h3>
              <div className="space-y-2">
                {advancedStats?.detections_by_severity?.length ? (
                  advancedStats.detections_by_severity.map((item: { severity: string; count: number }) => {
                    const colors = riskLevelColors[item.severity.toLowerCase()] || riskLevelColors.medium;
                    return (
                      <div key={item.severity} className="flex justify-between items-center py-1">
                        <span className={`text-sm capitalize ${colors.text}`}>{item.severity}</span>
                        <span className="text-white font-medium">{item.count}</span>
                      </div>
                    );
                  })
                ) : (
                  <p className="text-gray-500 text-sm">No detections yet</p>
                )}
              </div>
            </div>
          </div>

          {/* Detection List */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-gray-700">
              <h3 className="text-lg font-medium text-white">Recent Advanced Detections</h3>
            </div>
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Detection</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Type</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Severity</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Confidence</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Status</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Detected</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loadingDetections ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-gray-400">
                      <RefreshCw className="w-6 h-6 animate-spin mx-auto" />
                    </td>
                  </tr>
                ) : detections.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-gray-400">
                      No advanced detections found. Run detection algorithms to find threats.
                    </td>
                  </tr>
                ) : (
                  detections.map((detection: UebaAdvancedDetection) => {
                    const severityColors = riskLevelColors[detection.severity.toLowerCase()] || riskLevelColors.medium;
                    const statusColors = anomalyStatusColors[detection.status] || anomalyStatusColors.new;
                    return (
                      <tr key={detection.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                        <td className="px-4 py-3">
                          <p className="text-white font-medium">{detection.title}</p>
                          <p className="text-gray-500 text-xs">{detection.entity_id}</p>
                        </td>
                        <td className="px-4 py-3 text-gray-300 capitalize text-sm">
                          {detection.detection_type.replace(/_/g, ' ')}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 text-xs rounded ${severityColors.bg} ${severityColors.text}`}>
                            {detection.severity}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-300">
                          {(detection.confidence * 100).toFixed(0)}%
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 text-xs rounded ${statusColors.bg} ${statusColors.text}`}>
                            {detection.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-400 text-sm">
                          {new Date(detection.detected_at).toLocaleString()}
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => setSelectedDetection(detection)}
                            className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-white"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Configuration Sub Tab */}
      {activeSubTab === 'config' && (
        <div className="space-y-6">
          {/* Business Hours */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-medium text-white flex items-center gap-2">
                <Clock className="w-5 h-5 text-cyan-400" />
                Business Hours
              </h3>
              <Button size="sm" onClick={() => setShowBusinessHoursModal(true)}>
                <Plus className="w-4 h-4 mr-1" /> Add
              </Button>
            </div>
            <div className="space-y-2">
              {businessHours.length === 0 ? (
                <p className="text-gray-500 text-sm">No business hours configured. Off-hours detection uses 9 AM - 5 PM weekdays by default.</p>
              ) : (
                businessHours.map((hours: UebaBusinessHours) => (
                  <div key={hours.id} className="flex items-center justify-between py-2 border-b border-gray-700 last:border-0">
                    <div>
                      <p className="text-white font-medium">{hours.name}</p>
                      <p className="text-gray-500 text-xs">Timezone: {hours.timezone}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      {hours.is_default && (
                        <span className="px-2 py-1 text-xs rounded bg-cyan-500/20 text-cyan-400">Default</span>
                      )}
                      <button
                        onClick={() => deleteBusinessHoursMutation.mutate(hours.id)}
                        className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-red-400"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Sensitive Resources */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-medium text-white flex items-center gap-2">
                <Database className="w-5 h-5 text-orange-400" />
                Sensitive Resources
              </h3>
              <Button size="sm" onClick={() => setShowSensitiveResourceModal(true)}>
                <Plus className="w-4 h-4 mr-1" /> Add
              </Button>
            </div>
            <div className="space-y-2">
              {sensitiveResources.length === 0 ? (
                <p className="text-gray-500 text-sm">No sensitive resources defined. Add resources to enable unusual data access detection.</p>
              ) : (
                sensitiveResources.map((resource: UebaSensitiveResource) => {
                  const sensColors = sensitivityColors[resource.sensitivity_level] || sensitivityColors.internal;
                  return (
                    <div key={resource.id} className="flex items-center justify-between py-2 border-b border-gray-700 last:border-0">
                      <div>
                        <p className="text-white font-medium">{resource.name}</p>
                        <p className="text-gray-500 text-xs">Pattern: {resource.resource_pattern}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-1 text-xs rounded ${sensColors.bg} ${sensColors.text} capitalize`}>
                          {resource.sensitivity_level.replace(/_/g, ' ')}
                        </span>
                        <button
                          onClick={() => deleteSensitiveResourceMutation.mutate(resource.id)}
                          className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-red-400"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Known VPNs */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-medium text-white flex items-center gap-2">
                <Globe className="w-5 h-5 text-purple-400" />
                Known VPNs / Proxies
              </h3>
              <Button size="sm" onClick={() => setShowKnownVpnModal(true)}>
                <Plus className="w-4 h-4 mr-1" /> Add
              </Button>
            </div>
            <div className="space-y-2">
              {knownVpns.length === 0 ? (
                <p className="text-gray-500 text-sm">No known VPNs configured. Add corporate VPNs to reduce false positives in impossible travel detection.</p>
              ) : (
                knownVpns.map((vpn: UebaKnownVpn) => (
                  <div key={vpn.id} className="flex items-center justify-between py-2 border-b border-gray-700 last:border-0">
                    <div>
                      <p className="text-white font-medium">{vpn.name}</p>
                      <p className="text-gray-500 text-xs">{vpn.provider || 'Unknown provider'}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      {vpn.is_corporate && (
                        <span className="px-2 py-1 text-xs rounded bg-blue-500/20 text-blue-400">Corporate</span>
                      )}
                      {vpn.is_trusted && (
                        <span className="px-2 py-1 text-xs rounded bg-green-500/20 text-green-400">Trusted</span>
                      )}
                      <button
                        onClick={() => deleteKnownVpnMutation.mutate(vpn.id)}
                        className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-red-400"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Detection Rules */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-medium text-white flex items-center gap-2">
                <Settings2 className="w-5 h-5 text-yellow-400" />
                Detection Rules
              </h3>
              <Button size="sm" onClick={() => setShowDetectionRuleModal(true)}>
                <Plus className="w-4 h-4 mr-1" /> Add
              </Button>
            </div>
            <div className="space-y-2">
              {detectionRules.length === 0 ? (
                <p className="text-gray-500 text-sm">No custom detection rules. Default detection algorithms are always active.</p>
              ) : (
                detectionRules.map((rule: UebaDetectionRule) => {
                  const severityColors = riskLevelColors[rule.severity.toLowerCase()] || riskLevelColors.medium;
                  return (
                    <div key={rule.id} className="flex items-center justify-between py-2 border-b border-gray-700 last:border-0">
                      <div>
                        <p className="text-white font-medium">{rule.name}</p>
                        <p className="text-gray-500 text-xs capitalize">{rule.detection_type.replace(/_/g, ' ')}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-1 text-xs rounded ${severityColors.bg} ${severityColors.text}`}>
                          {rule.severity}
                        </span>
                        <span className={`px-2 py-1 text-xs rounded ${rule.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>
                          {rule.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                        <button
                          onClick={() => deleteDetectionRuleMutation.mutate(rule.id)}
                          className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-red-400"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}

      {/* Run Detection Sub Tab */}
      {activeSubTab === 'data' && (
        <div className="space-y-6">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <h3 className="text-lg font-medium text-white mb-4">Run Advanced Detection Algorithms</h3>
            <p className="text-gray-400 text-sm mb-6">
              Execute behavioral detection algorithms against collected activity data. Each algorithm analyzes the last 24 hours of data.
            </p>
            <div className="grid grid-cols-2 gap-4">
              {detectionTypes.map((detection) => (
                <div key={detection.id} className="bg-gray-900 border border-gray-700 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <div className="p-2 bg-cyan-500/20 rounded-lg">
                      {detection.icon}
                    </div>
                    <div className="flex-1">
                      <h4 className="text-white font-medium">{detection.label}</h4>
                      <p className="text-gray-500 text-sm mt-1">{detection.description}</p>
                    </div>
                    <Button
                      size="sm"
                      onClick={() => runDetectionMutation.mutate(detection.id)}
                      loading={runDetectionMutation.isPending}
                    >
                      <Play className="w-4 h-4 mr-1" /> Run
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Run All Button */}
          <div className="flex justify-center">
            <Button
              size="lg"
              onClick={async () => {
                for (const detection of detectionTypes) {
                  await runDetectionMutation.mutateAsync(detection.id);
                }
              }}
              loading={runDetectionMutation.isPending}
            >
              <Radar className="w-5 h-5 mr-2" /> Run All Detection Algorithms
            </Button>
          </div>
        </div>
      )}

      {/* Detection Detail Modal */}
      {selectedDetection && (
        <Modal isOpen={true} onClose={() => setSelectedDetection(null)} title="Detection Details" size="xl">
          <div className="space-y-4">
            <div className="flex items-start gap-4">
              <div className={`p-3 rounded-lg ${riskLevelColors[selectedDetection.severity.toLowerCase()]?.bg || 'bg-orange-500/20'}`}>
                <Radar className="w-8 h-8 text-orange-400" />
              </div>
              <div className="flex-1">
                <h3 className="text-xl font-bold text-white">{selectedDetection.title}</h3>
                <p className="text-gray-400 mt-1">{selectedDetection.description}</p>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4">
              <div className="bg-gray-900 rounded-lg p-3">
                <p className="text-gray-500 text-sm">Type</p>
                <p className="text-white capitalize">{selectedDetection.detection_type.replace(/_/g, ' ')}</p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3">
                <p className="text-gray-500 text-sm">Severity</p>
                <p className={`capitalize ${riskLevelColors[selectedDetection.severity.toLowerCase()]?.text || 'text-white'}`}>
                  {selectedDetection.severity}
                </p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3">
                <p className="text-gray-500 text-sm">Confidence</p>
                <p className="text-white">{(selectedDetection.confidence * 100).toFixed(0)}%</p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3">
                <p className="text-gray-500 text-sm">Risk Score</p>
                <p className="text-orange-400">+{selectedDetection.risk_score}</p>
              </div>
            </div>

            <div className="bg-gray-900 rounded-lg p-4">
              <h4 className="text-white font-medium mb-2">Evidence</h4>
              <pre className="text-gray-400 text-sm whitespace-pre-wrap overflow-auto max-h-48">
                {selectedDetection.evidence}
              </pre>
            </div>

            {selectedDetection.geolocation_data && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-white font-medium mb-2">Geolocation Data</h4>
                <pre className="text-gray-400 text-sm whitespace-pre-wrap overflow-auto max-h-32">
                  {selectedDetection.geolocation_data}
                </pre>
              </div>
            )}

            {selectedDetection.mitre_techniques && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-white font-medium mb-2">MITRE ATT&CK Techniques</h4>
                <div className="flex flex-wrap gap-2">
                  {JSON.parse(selectedDetection.mitre_techniques).map((technique: string) => (
                    <span key={technique} className="px-2 py-1 bg-purple-500/20 text-purple-400 text-sm rounded">
                      {technique}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Modal>
      )}

      {/* Business Hours Modal */}
      <Modal isOpen={showBusinessHoursModal} onClose={() => setShowBusinessHoursModal(false)} title="Add Business Hours">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const form = e.target as HTMLFormElement;
            const formData = new FormData(form);
            createBusinessHoursMutation.mutate({
              name: formData.get('name') as string,
              timezone: formData.get('timezone') as string,
              monday_start: formData.get('monday_start') as string || undefined,
              monday_end: formData.get('monday_end') as string || undefined,
              tuesday_start: formData.get('tuesday_start') as string || undefined,
              tuesday_end: formData.get('tuesday_end') as string || undefined,
              wednesday_start: formData.get('wednesday_start') as string || undefined,
              wednesday_end: formData.get('wednesday_end') as string || undefined,
              thursday_start: formData.get('thursday_start') as string || undefined,
              thursday_end: formData.get('thursday_end') as string || undefined,
              friday_start: formData.get('friday_start') as string || undefined,
              friday_end: formData.get('friday_end') as string || undefined,
              is_default: (formData.get('is_default') as string) === 'on',
            });
          }}
          className="space-y-4"
        >
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Name *</label>
              <input name="name" type="text" required className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Timezone *</label>
              <select name="timezone" required className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white">
                <option value="America/New_York">America/New_York</option>
                <option value="America/Los_Angeles">America/Los_Angeles</option>
                <option value="America/Chicago">America/Chicago</option>
                <option value="Europe/London">Europe/London</option>
                <option value="Europe/Berlin">Europe/Berlin</option>
                <option value="Asia/Tokyo">Asia/Tokyo</option>
                <option value="UTC">UTC</option>
              </select>
            </div>
          </div>
          <div className="text-sm text-gray-400 mb-2">Business hours (24h format, e.g., 09:00)</div>
          {['monday', 'tuesday', 'wednesday', 'thursday', 'friday'].map((day) => (
            <div key={day} className="grid grid-cols-3 gap-4 items-center">
              <span className="text-gray-300 capitalize">{day}</span>
              <input name={`${day}_start`} type="text" placeholder="09:00" className="px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white" />
              <input name={`${day}_end`} type="text" placeholder="17:00" className="px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white" />
            </div>
          ))}
          <label className="flex items-center gap-2">
            <input type="checkbox" name="is_default" className="rounded border-gray-700 bg-gray-900 text-cyan-500" />
            <span className="text-gray-300">Set as default</span>
          </label>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
            <Button variant="secondary" onClick={() => setShowBusinessHoursModal(false)}>Cancel</Button>
            <Button type="submit" loading={createBusinessHoursMutation.isPending}>Create</Button>
          </div>
        </form>
      </Modal>

      {/* Sensitive Resource Modal */}
      <Modal isOpen={showSensitiveResourceModal} onClose={() => setShowSensitiveResourceModal(false)} title="Add Sensitive Resource">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const form = e.target as HTMLFormElement;
            const formData = new FormData(form);
            createSensitiveResourceMutation.mutate({
              name: formData.get('name') as string,
              resource_type: formData.get('resource_type') as string,
              resource_pattern: formData.get('resource_pattern') as string,
              sensitivity_level: formData.get('sensitivity_level') as string,
              alert_on_access: (formData.get('alert_on_access') as string) === 'on',
            });
          }}
          className="space-y-4"
        >
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Name *</label>
            <input name="name" type="text" required className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white" placeholder="e.g., Customer PII Database" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Resource Type *</label>
              <select name="resource_type" required className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white">
                <option value="database">Database</option>
                <option value="file_share">File Share</option>
                <option value="application">Application</option>
                <option value="api">API</option>
                <option value="bucket">Cloud Bucket</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Sensitivity Level *</label>
              <select name="sensitivity_level" required className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white">
                <option value="public">Public</option>
                <option value="internal">Internal</option>
                <option value="confidential">Confidential</option>
                <option value="restricted">Restricted</option>
                <option value="top_secret">Top Secret</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Resource Pattern *</label>
            <input name="resource_pattern" type="text" required className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white" placeholder="e.g., prod-customer-db or /data/confidential/*" />
          </div>
          <label className="flex items-center gap-2">
            <input type="checkbox" name="alert_on_access" className="rounded border-gray-700 bg-gray-900 text-cyan-500" />
            <span className="text-gray-300">Alert on any access</span>
          </label>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
            <Button variant="secondary" onClick={() => setShowSensitiveResourceModal(false)}>Cancel</Button>
            <Button type="submit" loading={createSensitiveResourceMutation.isPending}>Create</Button>
          </div>
        </form>
      </Modal>

      {/* Known VPN Modal */}
      <Modal isOpen={showKnownVpnModal} onClose={() => setShowKnownVpnModal(false)} title="Add Known VPN">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const form = e.target as HTMLFormElement;
            const formData = new FormData(form);
            const ipRangesStr = formData.get('ip_ranges') as string;
            createKnownVpnMutation.mutate({
              name: formData.get('name') as string,
              provider: formData.get('provider') as string || undefined,
              ip_ranges: ipRangesStr.split('\n').map(r => r.trim()).filter(r => r),
              is_corporate: (formData.get('is_corporate') as string) === 'on',
              is_trusted: (formData.get('is_trusted') as string) === 'on',
            });
          }}
          className="space-y-4"
        >
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Name *</label>
            <input name="name" type="text" required className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white" placeholder="e.g., Corporate VPN" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Provider</label>
            <input name="provider" type="text" className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white" placeholder="e.g., Cisco, Palo Alto" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">IP Ranges (one per line) *</label>
            <textarea name="ip_ranges" required rows={3} className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white font-mono text-sm" placeholder="10.0.0.0/8&#10;192.168.1.0/24" />
          </div>
          <div className="flex gap-4">
            <label className="flex items-center gap-2">
              <input type="checkbox" name="is_corporate" className="rounded border-gray-700 bg-gray-900 text-cyan-500" />
              <span className="text-gray-300">Corporate VPN</span>
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" name="is_trusted" className="rounded border-gray-700 bg-gray-900 text-cyan-500" />
              <span className="text-gray-300">Trusted (reduce false positives)</span>
            </label>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
            <Button variant="secondary" onClick={() => setShowKnownVpnModal(false)}>Cancel</Button>
            <Button type="submit" loading={createKnownVpnMutation.isPending}>Create</Button>
          </div>
        </form>
      </Modal>

      {/* Detection Rule Modal */}
      <Modal isOpen={showDetectionRuleModal} onClose={() => setShowDetectionRuleModal(false)} title="Add Detection Rule">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const form = e.target as HTMLFormElement;
            const formData = new FormData(form);
            createDetectionRuleMutation.mutate({
              name: formData.get('name') as string,
              description: formData.get('description') as string || undefined,
              detection_type: formData.get('detection_type') as string,
              severity: formData.get('severity') as string,
              enabled: (formData.get('enabled') as string) === 'on',
              conditions: {},
              thresholds: {},
              actions: ['alert'],
              cooldown_minutes: parseInt(formData.get('cooldown_minutes') as string) || 60,
            });
          }}
          className="space-y-4"
        >
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Name *</label>
            <input name="name" type="text" required className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
            <textarea name="description" rows={2} className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Detection Type *</label>
              <select name="detection_type" required className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white">
                <option value="impossible_travel">Impossible Travel</option>
                <option value="unusual_data_access">Unusual Data Access</option>
                <option value="off_hours_activity">Off-Hours Activity</option>
                <option value="service_account_abuse">Service Account Abuse</option>
                <option value="lateral_movement">Lateral Movement</option>
                <option value="data_exfiltration">Data Exfiltration</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Severity *</label>
              <select name="severity" required className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white">
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Cooldown (minutes)</label>
            <input name="cooldown_minutes" type="number" defaultValue={60} min={1} className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white" />
          </div>
          <label className="flex items-center gap-2">
            <input type="checkbox" name="enabled" defaultChecked className="rounded border-gray-700 bg-gray-900 text-cyan-500" />
            <span className="text-gray-300">Enable rule</span>
          </label>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
            <Button variant="secondary" onClick={() => setShowDetectionRuleModal(false)}>Cancel</Button>
            <Button type="submit" loading={createDetectionRuleMutation.isPending}>Create</Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

// Main UEBA Page Component
export default function UebaPage() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <TrendingUp className="w-4 h-4" /> },
    { id: 'entities', label: 'Entities', icon: <Users className="w-4 h-4" /> },
    { id: 'anomalies', label: 'Anomalies', icon: <AlertTriangle className="w-4 h-4" /> },
    { id: 'activities', label: 'Activities', icon: <Activity className="w-4 h-4" /> },
    { id: 'sessions', label: 'Sessions', icon: <Globe className="w-4 h-4" /> },
    { id: 'peer-groups', label: 'Peer Groups', icon: <Users className="w-4 h-4" /> },
    { id: 'advanced', label: 'Advanced Detection', icon: <Radar className="w-4 h-4" /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Brain className="w-7 h-7 text-cyan-500" />
              User Entity Behavior Analytics
            </h1>
            <p className="text-gray-400 mt-1">
              Monitor user and entity behavior, detect anomalies, and assess risk
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-gray-700">
          <nav className="flex gap-4">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 -mb-px transition-colors ${
                  activeTab === tab.id
                    ? 'text-cyan-400 border-b-2 border-cyan-400'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div>
          {activeTab === 'dashboard' && <DashboardTab />}
          {activeTab === 'entities' && <EntitiesTab />}
          {activeTab === 'anomalies' && <AnomaliesTab />}
          {activeTab === 'activities' && <ActivitiesTab />}
          {activeTab === 'sessions' && <SessionsTab />}
          {activeTab === 'peer-groups' && <PeerGroupsTab />}
          {activeTab === 'advanced' && <AdvancedTab />}
        </div>
      </div>
    </Layout>
  );
}
