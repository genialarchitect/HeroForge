import React, { useState, useEffect } from 'react';
import Layout from '../components/layout/Layout';
import {
  Activity, Play, Square, Plus, Trash2, RefreshCw, AlertTriangle,
  Search, Filter, BarChart3, PieChart, Clock, Network, Zap,
  ArrowUpDown, ChevronDown, ChevronRight, CheckCircle, XCircle,
  Download, Eye, Settings
} from 'lucide-react';
import api from '../services/api';

// Types
interface FlowCollector {
  id: string;
  name: string;
  collector_type: 'netflow_v5' | 'netflow_v9' | 'ipfix' | 'sflow';
  listen_address: string;
  listen_port: number;
  status: 'stopped' | 'starting' | 'running' | 'error';
  flows_received: number;
  bytes_received: number;
  last_flow_at: string | null;
  error_message: string | null;
  created_at: string;
}

interface FlowRecord {
  id: string;
  collector_id: string;
  exporter_ip: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  protocol_name: string;
  packets: number;
  bytes: number;
  tcp_flags: number | null;
  start_time: string;
  end_time: string;
  duration_ms: number;
  src_as: number | null;
  dst_as: number | null;
  application: string | null;
  is_suspicious: boolean;
}

interface FlowAnomaly {
  id: string;
  collector_id: string | null;
  anomaly_type: string;
  severity: string;
  title: string;
  description: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  affected_ports: number[];
  evidence: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  flow_count: number;
  total_bytes: number;
  total_packets: number;
  is_acknowledged: boolean;
}

interface TopTalker {
  ip_address: string;
  total_bytes: number;
  total_packets: number;
  flow_count: number;
  percentage: number;
  geo_location: { country_code?: string; country_name?: string } | null;
}

interface FlowStats {
  total_flows: number;
  total_bytes: number;
  total_packets: number;
  unique_sources: number;
  unique_destinations: number;
  bytes_per_second: number;
  packets_per_second: number;
  flows_per_second: number;
  tcp_flows: number;
  udp_flows: number;
  icmp_flows: number;
}

interface TimelineEntry {
  timestamp: string;
  flows: number;
  bytes: number;
  packets: number;
}

interface Dashboard {
  collectors: { id: string; name: string; status: string; collector_type: string; flows_parsed: number; bytes_received: number }[];
  recent_anomalies: FlowAnomaly[];
  stats: FlowStats;
  top_sources: TopTalker[];
  top_destinations: TopTalker[];
}

// Helper functions
const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const formatNumber = (num: number): string => {
  if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(2) + 'K';
  return num.toString();
};

const collectorTypeLabels: Record<string, string> = {
  netflow_v5: 'NetFlow v5',
  netflow_v9: 'NetFlow v9',
  ipfix: 'IPFIX',
  sflow: 'sFlow',
};

const anomalyTypeLabels: Record<string, string> = {
  port_scan: 'Port Scan',
  network_scan: 'Network Scan',
  ddos_attack: 'DDoS Attack',
  data_exfiltration: 'Data Exfiltration',
  beaconing: 'Beaconing',
  unusual_protocol: 'Unusual Protocol',
  large_transfer: 'Large Transfer',
  suspicious_port: 'Suspicious Port',
  c2_communication: 'C2 Communication',
  lateral_movement: 'Lateral Movement',
  dns_tunneling: 'DNS Tunneling',
};

const severityColors: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/30 border-red-600',
  high: 'text-orange-400 bg-orange-900/30 border-orange-600',
  medium: 'text-yellow-400 bg-yellow-900/30 border-yellow-600',
  low: 'text-blue-400 bg-blue-900/30 border-blue-600',
};

// Components
const StatCard: React.FC<{ icon: React.ReactNode; label: string; value: string | number; subValue?: string; color?: string }> = ({
  icon, label, value, subValue, color = 'text-blue-400'
}) => (
  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
    <div className="flex items-center gap-3">
      <div className={`${color} p-2 bg-gray-700/50 rounded-lg`}>{icon}</div>
      <div>
        <p className="text-gray-400 text-sm">{label}</p>
        <p className="text-white text-xl font-semibold">{value}</p>
        {subValue && <p className="text-gray-500 text-xs">{subValue}</p>}
      </div>
    </div>
  </div>
);

const CollectorCard: React.FC<{
  collector: FlowCollector;
  onStart: () => void;
  onStop: () => void;
  onDelete: () => void;
}> = ({ collector, onStart, onStop, onDelete }) => {
  const statusColors: Record<string, string> = {
    running: 'bg-green-500',
    stopped: 'bg-gray-500',
    starting: 'bg-yellow-500 animate-pulse',
    error: 'bg-red-500',
  };

  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="flex items-start justify-between mb-3">
        <div>
          <h3 className="text-white font-medium">{collector.name}</h3>
          <p className="text-gray-400 text-sm">{collectorTypeLabels[collector.collector_type]}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${statusColors[collector.status]}`} />
          <span className="text-gray-400 text-sm capitalize">{collector.status}</span>
        </div>
      </div>

      <div className="space-y-2 mb-4">
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Listen Address</span>
          <span className="text-white">{collector.listen_address}:{collector.listen_port}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Flows Received</span>
          <span className="text-white">{formatNumber(collector.flows_received)}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Bytes Received</span>
          <span className="text-white">{formatBytes(collector.bytes_received)}</span>
        </div>
        {collector.error_message && (
          <p className="text-red-400 text-sm">{collector.error_message}</p>
        )}
      </div>

      <div className="flex gap-2">
        {collector.status === 'stopped' || collector.status === 'error' ? (
          <button
            onClick={onStart}
            className="flex-1 bg-green-600 hover:bg-green-700 text-white py-2 px-3 rounded text-sm flex items-center justify-center gap-1"
          >
            <Play className="w-4 h-4" /> Start
          </button>
        ) : (
          <button
            onClick={onStop}
            className="flex-1 bg-yellow-600 hover:bg-yellow-700 text-white py-2 px-3 rounded text-sm flex items-center justify-center gap-1"
          >
            <Square className="w-4 h-4" /> Stop
          </button>
        )}
        <button
          onClick={onDelete}
          className="bg-red-600 hover:bg-red-700 text-white py-2 px-3 rounded text-sm"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};

const CreateCollectorModal: React.FC<{ onClose: () => void; onCreated: () => void }> = ({ onClose, onCreated }) => {
  const [form, setForm] = useState({
    name: '',
    collector_type: 'netflow_v9' as const,
    listen_address: '0.0.0.0',
    listen_port: 2055,
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await api.post('/netflow/collectors', form);
      onCreated();
      onClose();
    } catch (error) {
      console.error('Failed to create collector:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md border border-gray-700">
        <h2 className="text-xl font-bold text-white mb-4">Create Flow Collector</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-gray-400 text-sm mb-1">Name</label>
            <input
              type="text"
              value={form.name}
              onChange={e => setForm({ ...form, name: e.target.value })}
              className="w-full bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 focus:border-blue-500 focus:outline-none"
              required
            />
          </div>
          <div>
            <label className="block text-gray-400 text-sm mb-1">Collector Type</label>
            <select
              value={form.collector_type}
              onChange={e => setForm({ ...form, collector_type: e.target.value as any })}
              className="w-full bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="netflow_v5">NetFlow v5</option>
              <option value="netflow_v9">NetFlow v9</option>
              <option value="ipfix">IPFIX (NetFlow v10)</option>
              <option value="sflow">sFlow v5</option>
            </select>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-gray-400 text-sm mb-1">Listen Address</label>
              <input
                type="text"
                value={form.listen_address}
                onChange={e => setForm({ ...form, listen_address: e.target.value })}
                className="w-full bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 focus:border-blue-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-gray-400 text-sm mb-1">Port</label>
              <input
                type="number"
                value={form.listen_port}
                onChange={e => setForm({ ...form, listen_port: parseInt(e.target.value) })}
                className="w-full bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 focus:border-blue-500 focus:outline-none"
              />
            </div>
          </div>
          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 bg-gray-700 hover:bg-gray-600 text-white py-2 rounded"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2 rounded disabled:opacity-50"
            >
              {loading ? 'Creating...' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const AnomalyCard: React.FC<{ anomaly: FlowAnomaly; onAcknowledge: () => void }> = ({ anomaly, onAcknowledge }) => (
  <div className={`bg-gray-800 rounded-lg p-4 border ${severityColors[anomaly.severity] || 'border-gray-700'}`}>
    <div className="flex items-start justify-between mb-2">
      <div>
        <span className={`text-xs px-2 py-0.5 rounded ${severityColors[anomaly.severity] || 'text-gray-400 bg-gray-700'}`}>
          {anomaly.severity.toUpperCase()}
        </span>
        <h4 className="text-white font-medium mt-1">{anomaly.title}</h4>
      </div>
      {anomaly.is_acknowledged ? (
        <CheckCircle className="w-5 h-5 text-green-500" />
      ) : (
        <button onClick={onAcknowledge} className="text-gray-400 hover:text-white">
          <XCircle className="w-5 h-5" />
        </button>
      )}
    </div>
    <p className="text-gray-400 text-sm mb-2">{anomaly.description}</p>
    <div className="flex flex-wrap gap-4 text-xs text-gray-500">
      <span>Type: {anomalyTypeLabels[anomaly.anomaly_type] || anomaly.anomaly_type}</span>
      <span>Flows: {formatNumber(anomaly.flow_count)}</span>
      <span>Bytes: {formatBytes(anomaly.total_bytes)}</span>
      {anomaly.source_ip && <span>Source: {anomaly.source_ip}</span>}
      {anomaly.destination_ip && <span>Dest: {anomaly.destination_ip}</span>}
    </div>
  </div>
);

// Main Page Component
const NetFlowAnalysisPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'collectors' | 'flows' | 'anomalies' | 'top-talkers'>('dashboard');
  const [collectors, setCollectors] = useState<FlowCollector[]>([]);
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [anomalies, setAnomalies] = useState<FlowAnomaly[]>([]);
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [topTalkers, setTopTalkers] = useState<{ sources: TopTalker[]; destinations: TopTalker[] }>({ sources: [], destinations: [] });
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Filters
  const [flowFilter, setFlowFilter] = useState({ protocol: '', srcIp: '', dstIp: '', suspicious: false });
  const [timeRange, setTimeRange] = useState('1h');

  const fetchDashboard = async () => {
    try {
      const res = await api.get('/netflow/dashboard');
      setDashboard(res.data);
    } catch (error) {
      console.error('Failed to fetch dashboard:', error);
    }
  };

  const fetchCollectors = async () => {
    try {
      const res = await api.get('/netflow/collectors');
      setCollectors(res.data.collectors || []);
    } catch (error) {
      console.error('Failed to fetch collectors:', error);
    }
  };

  const fetchFlows = async () => {
    try {
      const params = new URLSearchParams();
      params.append('limit', '100');
      if (flowFilter.protocol) params.append('protocol', flowFilter.protocol);
      if (flowFilter.srcIp) params.append('src_ip', flowFilter.srcIp);
      if (flowFilter.dstIp) params.append('dst_ip', flowFilter.dstIp);
      if (flowFilter.suspicious) params.append('suspicious', 'true');

      const res = await api.get(`/api/netflow/flows?${params.toString()}`);
      setFlows(res.data.flows || []);
    } catch (error) {
      console.error('Failed to fetch flows:', error);
    }
  };

  const fetchAnomalies = async () => {
    try {
      const res = await api.get('/netflow/anomalies?limit=50');
      setAnomalies(res.data.anomalies || []);
    } catch (error) {
      console.error('Failed to fetch anomalies:', error);
    }
  };

  const fetchTopTalkers = async () => {
    try {
      const [sourcesRes, destsRes] = await Promise.all([
        api.get(`/api/netflow/top-talkers?direction=source&period=${timeRange}&limit=10`),
        api.get(`/api/netflow/top-talkers?direction=destination&period=${timeRange}&limit=10`),
      ]);
      setTopTalkers({
        sources: sourcesRes.data.talkers || [],
        destinations: destsRes.data.talkers || [],
      });
    } catch (error) {
      console.error('Failed to fetch top talkers:', error);
    }
  };

  const handleStartCollector = async (id: string) => {
    try {
      await api.post(`/api/netflow/collectors/${id}/start`);
      fetchCollectors();
    } catch (error) {
      console.error('Failed to start collector:', error);
    }
  };

  const handleStopCollector = async (id: string) => {
    try {
      await api.post(`/api/netflow/collectors/${id}/stop`);
      fetchCollectors();
    } catch (error) {
      console.error('Failed to stop collector:', error);
    }
  };

  const handleDeleteCollector = async (id: string) => {
    if (!confirm('Are you sure you want to delete this collector?')) return;
    try {
      await api.delete(`/api/netflow/collectors/${id}`);
      fetchCollectors();
    } catch (error) {
      console.error('Failed to delete collector:', error);
    }
  };

  const handleAcknowledgeAnomaly = async (id: string) => {
    try {
      await api.post(`/api/netflow/anomalies/${id}/acknowledge`, { notes: '' });
      fetchAnomalies();
      fetchDashboard();
    } catch (error) {
      console.error('Failed to acknowledge anomaly:', error);
    }
  };

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      await Promise.all([
        fetchDashboard(),
        fetchCollectors(),
        fetchFlows(),
        fetchAnomalies(),
        fetchTopTalkers(),
      ]);
      setLoading(false);
    };
    load();
  }, []);

  useEffect(() => {
    if (activeTab === 'flows') fetchFlows();
    if (activeTab === 'top-talkers') fetchTopTalkers();
  }, [flowFilter, timeRange]);

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="w-8 h-8 text-blue-400 animate-spin" />
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Activity className="w-8 h-8 text-blue-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">NetFlow Analysis</h1>
              <p className="text-gray-400 text-sm">Network traffic flow collection and analysis</p>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => {
                fetchDashboard();
                fetchCollectors();
                fetchFlows();
                fetchAnomalies();
                fetchTopTalkers();
              }}
              className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded flex items-center gap-2"
            >
              <RefreshCw className="w-4 h-4" /> Refresh
            </button>
            <button
              onClick={() => setShowCreateModal(true)}
              className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded flex items-center gap-2"
            >
              <Plus className="w-4 h-4" /> Add Collector
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-gray-800 rounded-lg p-1 w-fit">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
            { id: 'collectors', label: 'Collectors', icon: Network },
            { id: 'flows', label: 'Flow Records', icon: Activity },
            { id: 'anomalies', label: 'Anomalies', icon: AlertTriangle },
            { id: 'top-talkers', label: 'Top Talkers', icon: ArrowUpDown },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4 py-2 rounded flex items-center gap-2 text-sm ${
                activeTab === tab.id
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && dashboard && (
          <div className="space-y-6">
            {/* Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
              <StatCard
                icon={<Activity className="w-5 h-5" />}
                label="Total Flows"
                value={formatNumber(dashboard.stats.total_flows)}
              />
              <StatCard
                icon={<Zap className="w-5 h-5" />}
                label="Total Bytes"
                value={formatBytes(dashboard.stats.total_bytes)}
                color="text-green-400"
              />
              <StatCard
                icon={<BarChart3 className="w-5 h-5" />}
                label="Total Packets"
                value={formatNumber(dashboard.stats.total_packets)}
                color="text-purple-400"
              />
              <StatCard
                icon={<Network className="w-5 h-5" />}
                label="Unique Sources"
                value={formatNumber(dashboard.stats.unique_sources)}
                color="text-yellow-400"
              />
              <StatCard
                icon={<Network className="w-5 h-5" />}
                label="Unique Dests"
                value={formatNumber(dashboard.stats.unique_destinations)}
                color="text-orange-400"
              />
              <StatCard
                icon={<Clock className="w-5 h-5" />}
                label="Bytes/sec"
                value={formatBytes(dashboard.stats.bytes_per_second)}
                subValue="/sec"
                color="text-cyan-400"
              />
            </div>

            {/* Protocol Distribution */}
            <div className="grid md:grid-cols-3 gap-6">
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h3 className="text-white font-medium mb-4">Protocol Distribution</h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">TCP</span>
                    <span className="text-white">{formatNumber(dashboard.stats.tcp_flows)}</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div
                      className="bg-blue-500 h-2 rounded-full"
                      style={{ width: `${dashboard.stats.total_flows > 0 ? (dashboard.stats.tcp_flows / dashboard.stats.total_flows) * 100 : 0}%` }}
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">UDP</span>
                    <span className="text-white">{formatNumber(dashboard.stats.udp_flows)}</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div
                      className="bg-green-500 h-2 rounded-full"
                      style={{ width: `${dashboard.stats.total_flows > 0 ? (dashboard.stats.udp_flows / dashboard.stats.total_flows) * 100 : 0}%` }}
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">ICMP</span>
                    <span className="text-white">{formatNumber(dashboard.stats.icmp_flows)}</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div
                      className="bg-yellow-500 h-2 rounded-full"
                      style={{ width: `${dashboard.stats.total_flows > 0 ? (dashboard.stats.icmp_flows / dashboard.stats.total_flows) * 100 : 0}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Collectors Status */}
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h3 className="text-white font-medium mb-4">Collectors Status</h3>
                {dashboard.collectors.length === 0 ? (
                  <p className="text-gray-400 text-sm">No collectors configured</p>
                ) : (
                  <div className="space-y-2">
                    {dashboard.collectors.map(c => (
                      <div key={c.id} className="flex items-center justify-between py-2 border-b border-gray-700 last:border-0">
                        <div className="flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full ${c.status === 'running' ? 'bg-green-500' : 'bg-gray-500'}`} />
                          <span className="text-white text-sm">{c.name}</span>
                        </div>
                        <span className="text-gray-400 text-xs">{formatNumber(c.flows_parsed)} flows</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Recent Anomalies */}
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-400" />
                  Recent Anomalies
                </h3>
                {dashboard.recent_anomalies.length === 0 ? (
                  <p className="text-gray-400 text-sm">No anomalies detected</p>
                ) : (
                  <div className="space-y-2">
                    {dashboard.recent_anomalies.slice(0, 5).map(a => (
                      <div key={a.id} className="py-2 border-b border-gray-700 last:border-0">
                        <div className="flex items-center gap-2">
                          <span className={`text-xs px-1.5 py-0.5 rounded ${severityColors[a.severity] || 'text-gray-400 bg-gray-700'}`}>
                            {a.severity.toUpperCase()}
                          </span>
                          <span className="text-white text-sm truncate">{a.title}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Top Talkers Preview */}
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h3 className="text-white font-medium mb-4">Top Sources</h3>
                <div className="space-y-2">
                  {(dashboard.top_sources || []).slice(0, 5).map((t, i) => (
                    <div key={i} className="flex items-center justify-between py-1">
                      <span className="text-gray-300 text-sm font-mono">{t.ip_address}</span>
                      <span className="text-gray-400 text-sm">{formatBytes(t.total_bytes)}</span>
                    </div>
                  ))}
                  {(!dashboard.top_sources || dashboard.top_sources.length === 0) && (
                    <p className="text-gray-400 text-sm">No data available</p>
                  )}
                </div>
              </div>
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h3 className="text-white font-medium mb-4">Top Destinations</h3>
                <div className="space-y-2">
                  {(dashboard.top_destinations || []).slice(0, 5).map((t, i) => (
                    <div key={i} className="flex items-center justify-between py-1">
                      <span className="text-gray-300 text-sm font-mono">{t.ip_address}</span>
                      <span className="text-gray-400 text-sm">{formatBytes(t.total_bytes)}</span>
                    </div>
                  ))}
                  {(!dashboard.top_destinations || dashboard.top_destinations.length === 0) && (
                    <p className="text-gray-400 text-sm">No data available</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Collectors Tab */}
        {activeTab === 'collectors' && (
          <div>
            {collectors.length === 0 ? (
              <div className="text-center py-12 bg-gray-800 rounded-lg border border-gray-700">
                <Network className="w-12 h-12 text-gray-500 mx-auto mb-4" />
                <h3 className="text-white text-lg font-medium mb-2">No Collectors Configured</h3>
                <p className="text-gray-400 mb-4">Create a flow collector to start receiving NetFlow/IPFIX/sFlow data</p>
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded flex items-center gap-2 mx-auto"
                >
                  <Plus className="w-4 h-4" /> Create Collector
                </button>
              </div>
            ) : (
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                {collectors.map(c => (
                  <CollectorCard
                    key={c.id}
                    collector={c}
                    onStart={() => handleStartCollector(c.id)}
                    onStop={() => handleStopCollector(c.id)}
                    onDelete={() => handleDeleteCollector(c.id)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Flows Tab */}
        {activeTab === 'flows' && (
          <div>
            {/* Filters */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 mb-4">
              <div className="flex flex-wrap gap-4 items-end">
                <div>
                  <label className="block text-gray-400 text-xs mb-1">Protocol</label>
                  <select
                    value={flowFilter.protocol}
                    onChange={e => setFlowFilter({ ...flowFilter, protocol: e.target.value })}
                    className="bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 text-sm"
                  >
                    <option value="">All</option>
                    <option value="6">TCP</option>
                    <option value="17">UDP</option>
                    <option value="1">ICMP</option>
                  </select>
                </div>
                <div>
                  <label className="block text-gray-400 text-xs mb-1">Source IP</label>
                  <input
                    type="text"
                    value={flowFilter.srcIp}
                    onChange={e => setFlowFilter({ ...flowFilter, srcIp: e.target.value })}
                    placeholder="e.g., 192.168.1.1"
                    className="bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 text-sm w-40"
                  />
                </div>
                <div>
                  <label className="block text-gray-400 text-xs mb-1">Destination IP</label>
                  <input
                    type="text"
                    value={flowFilter.dstIp}
                    onChange={e => setFlowFilter({ ...flowFilter, dstIp: e.target.value })}
                    placeholder="e.g., 10.0.0.1"
                    className="bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 text-sm w-40"
                  />
                </div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={flowFilter.suspicious}
                    onChange={e => setFlowFilter({ ...flowFilter, suspicious: e.target.checked })}
                    className="rounded bg-gray-700 border-gray-600"
                  />
                  <span className="text-gray-300 text-sm">Suspicious only</span>
                </label>
                <button
                  onClick={fetchFlows}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm flex items-center gap-2"
                >
                  <Search className="w-4 h-4" /> Search
                </button>
              </div>
            </div>

            {/* Flows Table */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-gray-700">
                    <tr>
                      <th className="text-left text-gray-300 font-medium px-4 py-3">Source</th>
                      <th className="text-left text-gray-300 font-medium px-4 py-3">Destination</th>
                      <th className="text-left text-gray-300 font-medium px-4 py-3">Protocol</th>
                      <th className="text-right text-gray-300 font-medium px-4 py-3">Packets</th>
                      <th className="text-right text-gray-300 font-medium px-4 py-3">Bytes</th>
                      <th className="text-left text-gray-300 font-medium px-4 py-3">Application</th>
                      <th className="text-left text-gray-300 font-medium px-4 py-3">Time</th>
                      <th className="text-center text-gray-300 font-medium px-4 py-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700">
                    {flows.map(f => (
                      <tr key={f.id} className="hover:bg-gray-700/50">
                        <td className="px-4 py-3">
                          <span className="text-white font-mono">{f.src_ip}</span>
                          <span className="text-gray-500">:{f.src_port}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-white font-mono">{f.dst_ip}</span>
                          <span className="text-gray-500">:{f.dst_port}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            f.protocol === 6 ? 'bg-blue-900/50 text-blue-400' :
                            f.protocol === 17 ? 'bg-green-900/50 text-green-400' :
                            'bg-gray-700 text-gray-300'
                          }`}>
                            {f.protocol_name}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right text-gray-300">{formatNumber(f.packets)}</td>
                        <td className="px-4 py-3 text-right text-gray-300">{formatBytes(f.bytes)}</td>
                        <td className="px-4 py-3 text-gray-400">{f.application || '-'}</td>
                        <td className="px-4 py-3 text-gray-400 text-xs">
                          {new Date(f.start_time).toLocaleTimeString()}
                        </td>
                        <td className="px-4 py-3 text-center">
                          {f.is_suspicious && (
                            <span className="text-red-400" title="Suspicious">
                              <AlertTriangle className="w-4 h-4" />
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                    {flows.length === 0 && (
                      <tr>
                        <td colSpan={8} className="text-center py-8 text-gray-400">
                          No flow records found
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Anomalies Tab */}
        {activeTab === 'anomalies' && (
          <div className="space-y-4">
            {anomalies.length === 0 ? (
              <div className="text-center py-12 bg-gray-800 rounded-lg border border-gray-700">
                <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-4" />
                <h3 className="text-white text-lg font-medium mb-2">No Anomalies Detected</h3>
                <p className="text-gray-400">All network traffic appears normal</p>
              </div>
            ) : (
              <div className="grid md:grid-cols-2 gap-4">
                {anomalies.map(a => (
                  <AnomalyCard
                    key={a.id}
                    anomaly={a}
                    onAcknowledge={() => handleAcknowledgeAnomaly(a.id)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Top Talkers Tab */}
        {activeTab === 'top-talkers' && (
          <div>
            {/* Time Range Selector */}
            <div className="mb-4 flex items-center gap-4">
              <span className="text-gray-400">Time Range:</span>
              <div className="flex gap-2">
                {['1h', '6h', '24h', '7d'].map(range => (
                  <button
                    key={range}
                    onClick={() => setTimeRange(range)}
                    className={`px-3 py-1 rounded text-sm ${
                      timeRange === range
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                    }`}
                  >
                    {range}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
              {/* Top Sources */}
              <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
                <div className="px-4 py-3 bg-gray-700/50 border-b border-gray-700">
                  <h3 className="text-white font-medium">Top Sources by Traffic Volume</h3>
                </div>
                <div className="divide-y divide-gray-700">
                  {topTalkers.sources.map((t, i) => (
                    <div key={i} className="px-4 py-3 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-gray-500 w-6">{i + 1}.</span>
                        <div>
                          <span className="text-white font-mono">{t.ip_address}</span>
                          {t.geo_location?.country_code && (
                            <span className="text-gray-400 text-xs ml-2">
                              ({t.geo_location.country_code})
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-white">{formatBytes(t.total_bytes)}</p>
                        <p className="text-gray-400 text-xs">{formatNumber(t.flow_count)} flows</p>
                      </div>
                    </div>
                  ))}
                  {topTalkers.sources.length === 0 && (
                    <div className="px-4 py-8 text-center text-gray-400">No data available</div>
                  )}
                </div>
              </div>

              {/* Top Destinations */}
              <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
                <div className="px-4 py-3 bg-gray-700/50 border-b border-gray-700">
                  <h3 className="text-white font-medium">Top Destinations by Traffic Volume</h3>
                </div>
                <div className="divide-y divide-gray-700">
                  {topTalkers.destinations.map((t, i) => (
                    <div key={i} className="px-4 py-3 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-gray-500 w-6">{i + 1}.</span>
                        <div>
                          <span className="text-white font-mono">{t.ip_address}</span>
                          {t.geo_location?.country_code && (
                            <span className="text-gray-400 text-xs ml-2">
                              ({t.geo_location.country_code})
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-white">{formatBytes(t.total_bytes)}</p>
                        <p className="text-gray-400 text-xs">{formatNumber(t.flow_count)} flows</p>
                      </div>
                    </div>
                  ))}
                  {topTalkers.destinations.length === 0 && (
                    <div className="px-4 py-8 text-center text-gray-400">No data available</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Create Collector Modal */}
        {showCreateModal && (
          <CreateCollectorModal
            onClose={() => setShowCreateModal(false)}
            onCreated={fetchCollectors}
          />
        )}
      </div>
    </Layout>
  );
};

export default NetFlowAnalysisPage;
