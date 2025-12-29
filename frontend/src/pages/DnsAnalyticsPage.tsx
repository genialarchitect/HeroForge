import React, { useState, useEffect } from 'react';
import Layout from '../components/layout/Layout';
import {
  Activity, Globe, AlertTriangle, Shield, Search, RefreshCw,
  ChevronDown, ChevronRight, Eye, XCircle, CheckCircle,
  Filter, Download, Plus, Trash2, Zap, Brain, Network,
  Clock, BarChart3, Database
} from 'lucide-react';
import api from '../services/api';

// Types
interface DnsStats {
  total_queries: number;
  unique_domains: number;
  total_responses: number;
  suspicious_count: number;
}

interface NodStats {
  total_nods: number;
  high_risk_nods: number;
  recent_nods_24h: number;
  alerts_generated: number;
  unacknowledged_alerts: number;
}

interface DbStats {
  passive_dns_records: number;
  anomalies: number;
  newly_observed_domains: number;
  unacknowledged_alerts: number;
}

interface DgaAnalysis {
  domain: string;
  is_dga: boolean;
  probability: number;
  entropy: number;
  consonant_ratio: number;
  digit_ratio: number;
  detected_family: string | null;
}

interface AnalyzeDomainResponse {
  domain: string;
  dga_analysis: DgaAnalysis | null;
  is_dga: boolean;
  dga_probability: number | null;
  entropy: number | null;
  threat_indicators: string[];
}

interface PassiveDnsRecord {
  id: string;
  user_id: string;
  query_name: string;
  query_type: string;
  response_data: string;
  ttl: number | null;
  first_seen: string;
  last_seen: string;
  query_count: number;
  source_ips: string | null;
  is_suspicious: number;
  threat_type: string | null;
  threat_score: number;
  created_at: string;
}

interface DnsAnomaly {
  id: string;
  user_id: string;
  anomaly_type: string;
  domain: string;
  severity: string;
  description: string;
  indicators: string | null;
  entropy_score: number | null;
  dga_probability: number | null;
  first_seen: string;
  last_seen: string;
  query_count: number;
  status: string;
  notes: string | null;
  created_at: string;
}

interface NewlyObservedDomain {
  id: string;
  user_id: string;
  domain: string;
  tld: string;
  first_seen: string;
  last_seen: string | null;
  first_query_ip: string | null;
  risk_score: number;
  threat_indicators: string | null;
  threat_type: string | null;
  status: string;
  query_count: number;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

interface NodAlert {
  id: string;
  user_id: string;
  nod_id: string;
  domain: string;
  risk_score: number;
  severity: string;
  threat_type: string | null;
  indicators: string | null;
  first_seen: string;
  source_ip: string | null;
  acknowledged: number;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  created_at: string;
}

interface WhitelistEntry {
  id: string;
  user_id: string | null;
  domain: string;
  domain_type: string;
  reason: string | null;
  is_global: number;
  created_at: string;
}

interface DgaFamily {
  id: string;
  family_name: string;
  description: string | null;
  tld_patterns: string | null;
  length_min: number | null;
  length_max: number | null;
  entropy_min: number | null;
  entropy_max: number | null;
  example_domains: string | null;
  is_builtin: number;
}

// Helper functions
const severityColors: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/30 border-red-600',
  high: 'text-orange-400 bg-orange-900/30 border-orange-600',
  medium: 'text-yellow-400 bg-yellow-900/30 border-yellow-600',
  low: 'text-blue-400 bg-blue-900/30 border-blue-600',
  info: 'text-gray-400 bg-gray-900/30 border-gray-600',
};

const statusColors: Record<string, string> = {
  new: 'text-blue-400 bg-blue-900/30',
  investigating: 'text-yellow-400 bg-yellow-900/30',
  confirmed: 'text-orange-400 bg-orange-900/30',
  resolved: 'text-green-400 bg-green-900/30',
  false_positive: 'text-gray-400 bg-gray-900/30',
  whitelisted: 'text-gray-400 bg-gray-900/30',
};

const anomalyTypeLabels: Record<string, string> = {
  dga: 'DGA Domain',
  tunneling: 'DNS Tunneling',
  fast_flux: 'Fast-Flux',
  exfiltration: 'Data Exfiltration',
  high_entropy: 'High Entropy',
  suspicious_tld: 'Suspicious TLD',
  phishing: 'Phishing',
};

const formatDate = (dateStr: string): string => {
  return new Date(dateStr).toLocaleString();
};

// Components
const StatCard: React.FC<{
  icon: React.ReactNode;
  label: string;
  value: string | number;
  color?: string;
  onClick?: () => void;
}> = ({ icon, label, value, color = 'text-cyan-400', onClick }) => (
  <div
    className={`bg-gray-800 rounded-lg p-4 border border-gray-700 ${onClick ? 'cursor-pointer hover:border-cyan-600' : ''}`}
    onClick={onClick}
  >
    <div className="flex items-center gap-3">
      <div className={color}>{icon}</div>
      <div>
        <div className="text-sm text-gray-400">{label}</div>
        <div className="text-2xl font-bold text-white">{value}</div>
      </div>
    </div>
  </div>
);

const DnsAnalyticsPage: React.FC = () => {
  // State
  const [activeTab, setActiveTab] = useState<'dashboard' | 'analyze' | 'passive' | 'anomalies' | 'nods' | 'alerts' | 'whitelist' | 'families'>('dashboard');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Dashboard state
  const [dnsStats, setDnsStats] = useState<DnsStats | null>(null);
  const [nodStats, setNodStats] = useState<NodStats | null>(null);
  const [dbStats, setDbStats] = useState<DbStats | null>(null);

  // Analyze state
  const [analyzeDomain, setAnalyzeDomain] = useState('');
  const [batchDomains, setBatchDomains] = useState('');
  const [analyzeResult, setAnalyzeResult] = useState<AnalyzeDomainResponse | null>(null);
  const [batchResults, setBatchResults] = useState<AnalyzeDomainResponse[]>([]);
  const [analyzing, setAnalyzing] = useState(false);

  // Data lists
  const [passiveRecords, setPassiveRecords] = useState<PassiveDnsRecord[]>([]);
  const [anomalies, setAnomalies] = useState<DnsAnomaly[]>([]);
  const [nods, setNods] = useState<NewlyObservedDomain[]>([]);
  const [alerts, setAlerts] = useState<NodAlert[]>([]);
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([]);
  const [dgaFamilies, setDgaFamilies] = useState<DgaFamily[]>([]);

  // Filters
  const [domainFilter, setDomainFilter] = useState('');
  const [showOnlyUnacked, setShowOnlyUnacked] = useState(false);

  // Whitelist form
  const [newWhitelistDomain, setNewWhitelistDomain] = useState('');
  const [newWhitelistReason, setNewWhitelistReason] = useState('');

  // Fetch dashboard data
  const fetchDashboard = async () => {
    setLoading(true);
    try {
      const [statsRes, dashboardRes] = await Promise.all([
        api.get('/api/dns-analytics/stats'),
        api.get('/api/dns-analytics/dashboard'),
      ]);
      setDnsStats(statsRes.data.dns_stats);
      setNodStats(statsRes.data.nod_stats);
      setDbStats(dashboardRes.data.db_stats);
      setError(null);
    } catch (err) {
      console.error('Failed to fetch dashboard:', err);
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  // Fetch passive DNS records
  const fetchPassiveRecords = async () => {
    try {
      const res = await api.get('/api/dns-analytics/passive-dns', {
        params: { domain: domainFilter || undefined, limit: 100 }
      });
      setPassiveRecords(res.data.records);
    } catch (err) {
      console.error('Failed to fetch passive DNS:', err);
    }
  };

  // Fetch anomalies
  const fetchAnomalies = async () => {
    try {
      const res = await api.get('/api/dns-analytics/anomalies', { params: { limit: 100 } });
      setAnomalies(res.data.anomalies);
    } catch (err) {
      console.error('Failed to fetch anomalies:', err);
    }
  };

  // Fetch NODs
  const fetchNods = async () => {
    try {
      const res = await api.get('/api/dns-analytics/nods', { params: { limit: 100 } });
      setNods(res.data.nods);
    } catch (err) {
      console.error('Failed to fetch NODs:', err);
    }
  };

  // Fetch alerts
  const fetchAlerts = async () => {
    try {
      const res = await api.get('/api/dns-analytics/alerts', {
        params: { acknowledged: showOnlyUnacked ? false : undefined, limit: 100 }
      });
      setAlerts(res.data.alerts);
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
    }
  };

  // Fetch whitelist
  const fetchWhitelist = async () => {
    try {
      const res = await api.get('/api/dns-analytics/whitelist');
      setWhitelist(res.data.whitelist);
    } catch (err) {
      console.error('Failed to fetch whitelist:', err);
    }
  };

  // Fetch DGA families
  const fetchDgaFamilies = async () => {
    try {
      const res = await api.get('/api/dns-analytics/dga-families');
      setDgaFamilies(res.data.families);
    } catch (err) {
      console.error('Failed to fetch DGA families:', err);
    }
  };

  // Analyze single domain
  const handleAnalyzeDomain = async () => {
    if (!analyzeDomain.trim()) return;
    setAnalyzing(true);
    try {
      const res = await api.post('/api/dns-analytics/analyze', { domain: analyzeDomain.trim() });
      setAnalyzeResult(res.data);
    } catch (err) {
      console.error('Failed to analyze domain:', err);
    } finally {
      setAnalyzing(false);
    }
  };

  // Batch analyze domains
  const handleBatchAnalyze = async () => {
    const domains = batchDomains.split('\n').map(d => d.trim()).filter(d => d);
    if (domains.length === 0) return;
    setAnalyzing(true);
    try {
      const res = await api.post('/api/dns-analytics/analyze/batch', { domains });
      setBatchResults(res.data.results);
    } catch (err) {
      console.error('Failed to batch analyze:', err);
    } finally {
      setAnalyzing(false);
    }
  };

  // Acknowledge alert
  const handleAcknowledgeAlert = async (alertId: string) => {
    try {
      await api.post(`/api/dns-analytics/alerts/${alertId}/acknowledge`);
      fetchAlerts();
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
    }
  };

  // Add to whitelist
  const handleAddToWhitelist = async () => {
    if (!newWhitelistDomain.trim()) return;
    try {
      await api.post('/api/dns-analytics/whitelist', {
        domain: newWhitelistDomain.trim(),
        reason: newWhitelistReason || undefined,
      });
      setNewWhitelistDomain('');
      setNewWhitelistReason('');
      fetchWhitelist();
    } catch (err) {
      console.error('Failed to add to whitelist:', err);
    }
  };

  // Remove from whitelist
  const handleRemoveFromWhitelist = async (entryId: string) => {
    try {
      await api.delete(`/api/dns-analytics/whitelist/${entryId}`);
      fetchWhitelist();
    } catch (err) {
      console.error('Failed to remove from whitelist:', err);
    }
  };

  // Initial load
  useEffect(() => {
    fetchDashboard();
  }, []);

  // Tab change effects
  useEffect(() => {
    if (activeTab === 'passive') fetchPassiveRecords();
    if (activeTab === 'anomalies') fetchAnomalies();
    if (activeTab === 'nods') fetchNods();
    if (activeTab === 'alerts') fetchAlerts();
    if (activeTab === 'whitelist') fetchWhitelist();
    if (activeTab === 'families') fetchDgaFamilies();
  }, [activeTab, domainFilter, showOnlyUnacked]);

  // Tab buttons
  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: <BarChart3 size={16} /> },
    { id: 'analyze', label: 'Analyze', icon: <Brain size={16} /> },
    { id: 'passive', label: 'Passive DNS', icon: <Database size={16} /> },
    { id: 'anomalies', label: 'Anomalies', icon: <AlertTriangle size={16} /> },
    { id: 'nods', label: 'NODs', icon: <Globe size={16} /> },
    { id: 'alerts', label: 'Alerts', icon: <Zap size={16} /> },
    { id: 'whitelist', label: 'Whitelist', icon: <Shield size={16} /> },
    { id: 'families', label: 'DGA Families', icon: <Network size={16} /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Activity className="text-cyan-400" />
              DNS Analytics
            </h1>
            <p className="text-gray-400 mt-1">
              DNS security analytics, DGA detection, and threat intelligence
            </p>
          </div>
          <button
            onClick={fetchDashboard}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600"
          >
            <RefreshCw size={16} />
            Refresh
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 overflow-x-auto pb-2">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg whitespace-nowrap transition-colors ${
                activeTab === tab.id
                  ? 'bg-cyan-600 text-white'
                  : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Error display */}
        {error && (
          <div className="bg-red-900/30 border border-red-600 rounded-lg p-4 text-red-400">
            {error}
          </div>
        )}

        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {loading ? (
              <div className="text-center text-gray-400 py-8">Loading...</div>
            ) : (
              <>
                {/* Stats Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                  <StatCard
                    icon={<Database size={24} />}
                    label="Passive DNS Records"
                    value={dbStats?.passive_dns_records || 0}
                    color="text-blue-400"
                  />
                  <StatCard
                    icon={<Globe size={24} />}
                    label="Unique Domains"
                    value={dnsStats?.unique_domains || 0}
                    color="text-cyan-400"
                  />
                  <StatCard
                    icon={<AlertTriangle size={24} />}
                    label="Anomalies"
                    value={dbStats?.anomalies || 0}
                    color="text-orange-400"
                    onClick={() => setActiveTab('anomalies')}
                  />
                  <StatCard
                    icon={<Globe size={24} />}
                    label="NODs"
                    value={dbStats?.newly_observed_domains || 0}
                    color="text-purple-400"
                    onClick={() => setActiveTab('nods')}
                  />
                  <StatCard
                    icon={<Zap size={24} />}
                    label="Unacked Alerts"
                    value={dbStats?.unacknowledged_alerts || 0}
                    color="text-red-400"
                    onClick={() => setActiveTab('alerts')}
                  />
                  <StatCard
                    icon={<Shield size={24} />}
                    label="High Risk NODs"
                    value={nodStats?.high_risk_nods || 0}
                    color="text-red-400"
                  />
                </div>

                {/* Quick Analysis */}
                <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                  <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <Brain className="text-cyan-400" />
                    Quick Domain Analysis
                  </h2>
                  <div className="flex gap-4">
                    <input
                      type="text"
                      value={analyzeDomain}
                      onChange={(e) => setAnalyzeDomain(e.target.value)}
                      placeholder="Enter domain to analyze (e.g., suspicious-domain.com)"
                      className="flex-1 bg-gray-700 text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-cyan-500 outline-none"
                      onKeyPress={(e) => e.key === 'Enter' && handleAnalyzeDomain()}
                    />
                    <button
                      onClick={handleAnalyzeDomain}
                      disabled={analyzing || !analyzeDomain.trim()}
                      className="px-6 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                    >
                      <Search size={16} />
                      Analyze
                    </button>
                  </div>

                  {analyzeResult && (
                    <div className="mt-4 p-4 bg-gray-900 rounded-lg border border-gray-700">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-mono text-cyan-400">{analyzeResult.domain}</span>
                        {analyzeResult.is_dga ? (
                          <span className="px-2 py-1 bg-red-900/30 text-red-400 rounded text-sm">
                            DGA Detected ({((analyzeResult.dga_probability || 0) * 100).toFixed(1)}%)
                          </span>
                        ) : (
                          <span className="px-2 py-1 bg-green-900/30 text-green-400 rounded text-sm">
                            Clean
                          </span>
                        )}
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <span className="text-gray-400">Entropy:</span>{' '}
                          <span className="text-white">{analyzeResult.entropy?.toFixed(2) || 'N/A'}</span>
                        </div>
                        <div>
                          <span className="text-gray-400">DGA Family:</span>{' '}
                          <span className="text-white">
                            {analyzeResult.dga_analysis?.detected_family || 'None'}
                          </span>
                        </div>
                      </div>
                      {analyzeResult.threat_indicators.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-2">
                          {analyzeResult.threat_indicators.map((indicator, i) => (
                            <span key={i} className="px-2 py-1 bg-orange-900/30 text-orange-400 rounded text-xs">
                              {indicator}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        )}

        {/* Analyze Tab */}
        {activeTab === 'analyze' && (
          <div className="space-y-6">
            {/* Single Domain Analysis */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h2 className="text-lg font-semibold text-white mb-4">Single Domain Analysis</h2>
              <div className="flex gap-4 mb-4">
                <input
                  type="text"
                  value={analyzeDomain}
                  onChange={(e) => setAnalyzeDomain(e.target.value)}
                  placeholder="Enter domain..."
                  className="flex-1 bg-gray-700 text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-cyan-500 outline-none"
                />
                <button
                  onClick={handleAnalyzeDomain}
                  disabled={analyzing}
                  className="px-6 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50"
                >
                  {analyzing ? 'Analyzing...' : 'Analyze'}
                </button>
              </div>

              {analyzeResult && (
                <div className="p-4 bg-gray-900 rounded-lg border border-gray-700">
                  <div className="flex items-center justify-between mb-4">
                    <span className="font-mono text-xl text-cyan-400">{analyzeResult.domain}</span>
                    {analyzeResult.is_dga ? (
                      <span className="px-3 py-1 bg-red-900/50 text-red-400 rounded-lg font-semibold">
                        DGA DETECTED
                      </span>
                    ) : (
                      <span className="px-3 py-1 bg-green-900/50 text-green-400 rounded-lg font-semibold">
                        CLEAN
                      </span>
                    )}
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-gray-800 rounded p-3">
                      <div className="text-gray-400 text-sm">DGA Probability</div>
                      <div className="text-white text-lg font-bold">
                        {((analyzeResult.dga_probability || 0) * 100).toFixed(1)}%
                      </div>
                    </div>
                    <div className="bg-gray-800 rounded p-3">
                      <div className="text-gray-400 text-sm">Entropy</div>
                      <div className="text-white text-lg font-bold">
                        {analyzeResult.entropy?.toFixed(3) || 'N/A'}
                      </div>
                    </div>
                    <div className="bg-gray-800 rounded p-3">
                      <div className="text-gray-400 text-sm">Consonant Ratio</div>
                      <div className="text-white text-lg font-bold">
                        {(analyzeResult.dga_analysis?.consonant_ratio || 0).toFixed(2)}
                      </div>
                    </div>
                    <div className="bg-gray-800 rounded p-3">
                      <div className="text-gray-400 text-sm">Digit Ratio</div>
                      <div className="text-white text-lg font-bold">
                        {(analyzeResult.dga_analysis?.digit_ratio || 0).toFixed(2)}
                      </div>
                    </div>
                  </div>

                  {analyzeResult.dga_analysis?.detected_family && (
                    <div className="mt-4 p-3 bg-red-900/20 rounded-lg border border-red-700">
                      <span className="text-red-400">
                        Detected DGA Family: <strong>{analyzeResult.dga_analysis.detected_family}</strong>
                      </span>
                    </div>
                  )}

                  {analyzeResult.threat_indicators.length > 0 && (
                    <div className="mt-4">
                      <div className="text-gray-400 text-sm mb-2">Threat Indicators</div>
                      <div className="flex flex-wrap gap-2">
                        {analyzeResult.threat_indicators.map((indicator, i) => (
                          <span
                            key={i}
                            className="px-3 py-1 bg-orange-900/30 text-orange-400 rounded"
                          >
                            {indicator}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Batch Analysis */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h2 className="text-lg font-semibold text-white mb-4">Batch Domain Analysis</h2>
              <textarea
                value={batchDomains}
                onChange={(e) => setBatchDomains(e.target.value)}
                placeholder="Enter domains (one per line)..."
                className="w-full h-32 bg-gray-700 text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-cyan-500 outline-none font-mono"
              />
              <button
                onClick={handleBatchAnalyze}
                disabled={analyzing}
                className="mt-4 px-6 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50"
              >
                {analyzing ? 'Analyzing...' : 'Analyze All'}
              </button>

              {batchResults.length > 0 && (
                <div className="mt-4 space-y-2">
                  {batchResults.map((result, i) => (
                    <div
                      key={i}
                      className={`p-3 rounded-lg border ${
                        result.is_dga ? 'bg-red-900/20 border-red-700' : 'bg-gray-900 border-gray-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-cyan-400">{result.domain}</span>
                        <div className="flex items-center gap-4">
                          <span className="text-gray-400 text-sm">
                            Entropy: {result.entropy?.toFixed(2)}
                          </span>
                          {result.is_dga ? (
                            <span className="text-red-400 text-sm">
                              DGA ({((result.dga_probability || 0) * 100).toFixed(0)}%)
                            </span>
                          ) : (
                            <span className="text-green-400 text-sm">Clean</span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Passive DNS Tab */}
        {activeTab === 'passive' && (
          <div className="space-y-4">
            <div className="flex gap-4 items-center">
              <input
                type="text"
                value={domainFilter}
                onChange={(e) => setDomainFilter(e.target.value)}
                placeholder="Filter by domain..."
                className="flex-1 bg-gray-700 text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-cyan-500 outline-none"
              />
              <button
                onClick={fetchPassiveRecords}
                className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-500"
              >
                <Search size={16} />
              </button>
            </div>

            <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
              <table className="w-full">
                <thead className="bg-gray-900">
                  <tr>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Domain</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Type</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Response</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Queries</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Last Seen</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {passiveRecords.map((record) => (
                    <tr key={record.id} className="hover:bg-gray-700/50">
                      <td className="px-4 py-3 font-mono text-cyan-400">{record.query_name}</td>
                      <td className="px-4 py-3 text-white">{record.query_type}</td>
                      <td className="px-4 py-3 text-gray-300 font-mono text-sm truncate max-w-xs">
                        {record.response_data}
                      </td>
                      <td className="px-4 py-3 text-white">{record.query_count}</td>
                      <td className="px-4 py-3 text-gray-400 text-sm">
                        {formatDate(record.last_seen)}
                      </td>
                      <td className="px-4 py-3">
                        {record.is_suspicious ? (
                          <span className="px-2 py-1 bg-red-900/30 text-red-400 rounded text-xs">
                            Suspicious
                          </span>
                        ) : (
                          <span className="px-2 py-1 bg-green-900/30 text-green-400 rounded text-xs">
                            Normal
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {passiveRecords.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                        No passive DNS records found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Anomalies Tab */}
        {activeTab === 'anomalies' && (
          <div className="space-y-4">
            <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
              <table className="w-full">
                <thead className="bg-gray-900">
                  <tr>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Domain</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Type</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Severity</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Status</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">First Seen</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {anomalies.map((anomaly) => (
                    <tr key={anomaly.id} className="hover:bg-gray-700/50">
                      <td className="px-4 py-3 font-mono text-cyan-400">{anomaly.domain}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-1 bg-purple-900/30 text-purple-400 rounded text-xs">
                          {anomalyTypeLabels[anomaly.anomaly_type] || anomaly.anomaly_type}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded text-xs border ${severityColors[anomaly.severity] || severityColors.info}`}>
                          {anomaly.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded text-xs ${statusColors[anomaly.status] || statusColors.new}`}>
                          {anomaly.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-sm">
                        {formatDate(anomaly.first_seen)}
                      </td>
                      <td className="px-4 py-3 text-gray-300 text-sm truncate max-w-md">
                        {anomaly.description}
                      </td>
                    </tr>
                  ))}
                  {anomalies.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                        No anomalies detected
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* NODs Tab */}
        {activeTab === 'nods' && (
          <div className="space-y-4">
            <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
              <table className="w-full">
                <thead className="bg-gray-900">
                  <tr>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Domain</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">TLD</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Risk Score</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Status</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Threat Type</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">First Seen</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Queries</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {nods.map((nod) => (
                    <tr key={nod.id} className="hover:bg-gray-700/50">
                      <td className="px-4 py-3 font-mono text-cyan-400">{nod.domain}</td>
                      <td className="px-4 py-3 text-gray-300">.{nod.tld}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div
                            className={`w-12 h-2 rounded-full ${
                              nod.risk_score >= 70
                                ? 'bg-red-500'
                                : nod.risk_score >= 40
                                ? 'bg-yellow-500'
                                : 'bg-green-500'
                            }`}
                            style={{ width: `${Math.max(nod.risk_score, 10)}%` }}
                          />
                          <span className="text-white">{nod.risk_score}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded text-xs ${statusColors[nod.status] || statusColors.new}`}>
                          {nod.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-300">
                        {nod.threat_type || '-'}
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-sm">
                        {formatDate(nod.first_seen)}
                      </td>
                      <td className="px-4 py-3 text-white">{nod.query_count}</td>
                    </tr>
                  ))}
                  {nods.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                        No newly observed domains found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Alerts Tab */}
        {activeTab === 'alerts' && (
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <label className="flex items-center gap-2 text-gray-400">
                <input
                  type="checkbox"
                  checked={showOnlyUnacked}
                  onChange={(e) => setShowOnlyUnacked(e.target.checked)}
                  className="rounded bg-gray-700 border-gray-600 text-cyan-500"
                />
                Show only unacknowledged
              </label>
            </div>

            <div className="space-y-4">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`bg-gray-800 rounded-lg p-4 border ${
                    alert.acknowledged ? 'border-gray-700' : 'border-red-600'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-1 rounded text-xs border ${severityColors[alert.severity] || severityColors.info}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      <span className="font-mono text-cyan-400">{alert.domain}</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className="text-gray-400 text-sm">
                        Risk Score: <strong className="text-white">{alert.risk_score}</strong>
                      </span>
                      {!alert.acknowledged && (
                        <button
                          onClick={() => handleAcknowledgeAlert(alert.id)}
                          className="flex items-center gap-1 px-3 py-1 bg-green-600 text-white rounded hover:bg-green-700 text-sm"
                        >
                          <CheckCircle size={14} />
                          Acknowledge
                        </button>
                      )}
                    </div>
                  </div>
                  <div className="text-sm text-gray-400">
                    {alert.threat_type && (
                      <span className="mr-4">Threat: {alert.threat_type}</span>
                    )}
                    <span>First seen: {formatDate(alert.first_seen)}</span>
                    {alert.source_ip && (
                      <span className="ml-4">Source: {alert.source_ip}</span>
                    )}
                  </div>
                  {alert.acknowledged && (
                    <div className="mt-2 text-xs text-green-400">
                      Acknowledged by {alert.acknowledged_by} at {formatDate(alert.acknowledged_at || '')}
                    </div>
                  )}
                </div>
              ))}
              {alerts.length === 0 && (
                <div className="text-center text-gray-500 py-8">
                  No alerts found
                </div>
              )}
            </div>
          </div>
        )}

        {/* Whitelist Tab */}
        {activeTab === 'whitelist' && (
          <div className="space-y-4">
            {/* Add to whitelist form */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h3 className="text-white font-semibold mb-4">Add Domain to Whitelist</h3>
              <div className="flex gap-4">
                <input
                  type="text"
                  value={newWhitelistDomain}
                  onChange={(e) => setNewWhitelistDomain(e.target.value)}
                  placeholder="Domain (e.g., example.com)"
                  className="flex-1 bg-gray-700 text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-cyan-500 outline-none"
                />
                <input
                  type="text"
                  value={newWhitelistReason}
                  onChange={(e) => setNewWhitelistReason(e.target.value)}
                  placeholder="Reason (optional)"
                  className="flex-1 bg-gray-700 text-white rounded-lg px-4 py-2 focus:ring-2 focus:ring-cyan-500 outline-none"
                />
                <button
                  onClick={handleAddToWhitelist}
                  disabled={!newWhitelistDomain.trim()}
                  className="px-6 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50 flex items-center gap-2"
                >
                  <Plus size={16} />
                  Add
                </button>
              </div>
            </div>

            {/* Whitelist table */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
              <table className="w-full">
                <thead className="bg-gray-900">
                  <tr>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Domain</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Type</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Reason</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Scope</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Added</th>
                    <th className="px-4 py-3 text-left text-gray-400 text-sm">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {whitelist.map((entry) => (
                    <tr key={entry.id} className="hover:bg-gray-700/50">
                      <td className="px-4 py-3 font-mono text-cyan-400">{entry.domain}</td>
                      <td className="px-4 py-3 text-gray-300">{entry.domain_type}</td>
                      <td className="px-4 py-3 text-gray-300">{entry.reason || '-'}</td>
                      <td className="px-4 py-3">
                        {entry.is_global ? (
                          <span className="px-2 py-1 bg-purple-900/30 text-purple-400 rounded text-xs">
                            Global
                          </span>
                        ) : (
                          <span className="px-2 py-1 bg-gray-900/30 text-gray-400 rounded text-xs">
                            Personal
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-sm">
                        {formatDate(entry.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        {!entry.is_global && (
                          <button
                            onClick={() => handleRemoveFromWhitelist(entry.id)}
                            className="text-red-400 hover:text-red-300"
                          >
                            <Trash2 size={16} />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {whitelist.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                        No whitelist entries
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* DGA Families Tab */}
        {activeTab === 'families' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {dgaFamilies.map((family) => (
                <div key={family.id} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-white font-semibold">{family.family_name}</h3>
                    {family.is_builtin ? (
                      <span className="px-2 py-1 bg-blue-900/30 text-blue-400 rounded text-xs">
                        Built-in
                      </span>
                    ) : (
                      <span className="px-2 py-1 bg-green-900/30 text-green-400 rounded text-xs">
                        Custom
                      </span>
                    )}
                  </div>
                  {family.description && (
                    <p className="text-gray-400 text-sm mb-3">{family.description}</p>
                  )}
                  <div className="text-sm space-y-1">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Length Range:</span>
                      <span className="text-white">
                        {family.length_min || '?'} - {family.length_max || '?'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Entropy Range:</span>
                      <span className="text-white">
                        {family.entropy_min?.toFixed(2) || '?'} - {family.entropy_max?.toFixed(2) || '?'}
                      </span>
                    </div>
                    {family.tld_patterns && (
                      <div className="flex justify-between">
                        <span className="text-gray-400">TLDs:</span>
                        <span className="text-white">{family.tld_patterns}</span>
                      </div>
                    )}
                  </div>
                  {family.example_domains && (
                    <div className="mt-3 pt-3 border-t border-gray-700">
                      <div className="text-gray-400 text-xs mb-1">Examples:</div>
                      <div className="font-mono text-xs text-cyan-400">
                        {family.example_domains}
                      </div>
                    </div>
                  )}
                </div>
              ))}
              {dgaFamilies.length === 0 && (
                <div className="col-span-full text-center text-gray-500 py-8">
                  No DGA families configured
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default DnsAnalyticsPage;
