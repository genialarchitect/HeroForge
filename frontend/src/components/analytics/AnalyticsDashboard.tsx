import React, { useState, useEffect } from 'react';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import {
  Activity,
  Server,
  Shield,
  AlertTriangle,
  TrendingUp,
  Calendar,
} from 'lucide-react';
import { analyticsAPI } from '../../services/api';
import type {
  AnalyticsSummary,
  TimeSeriesDataPoint,
  VulnerabilityTimeSeriesDataPoint,
  ServiceCount,
} from '../../types';
import Card from '../ui/Card';
import LoadingSpinner from '../ui/LoadingSpinner';

type DateRange = 7 | 30 | 90;

interface StatCardProps {
  title: string;
  value: number | string;
  subtitle?: string;
  icon: React.ReactNode;
  color: string;
  trend?: {
    value: number;
    isPositive: boolean;
  };
}

const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  color,
  trend,
}) => {
  return (
    <Card className="p-6">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-slate-400 text-sm font-medium mb-1">{title}</p>
          <p className={`text-3xl font-bold ${color} mb-1`}>{value}</p>
          {subtitle && <p className="text-slate-500 text-xs">{subtitle}</p>}
          {trend && (
            <div
              className={`flex items-center gap-1 mt-2 text-xs ${
                trend.isPositive ? 'text-green-400' : 'text-red-400'
              }`}
            >
              <TrendingUp
                className={`h-3 w-3 ${!trend.isPositive && 'rotate-180'}`}
              />
              <span>
                {trend.isPositive ? '+' : ''}
                {trend.value}%
              </span>
            </div>
          )}
        </div>
        <div className={`${color.replace('text-', 'bg-')}/20 p-3 rounded-lg`}>
          {icon}
        </div>
      </div>
    </Card>
  );
};

const AnalyticsDashboard: React.FC = () => {
  const [dateRange, setDateRange] = useState<DateRange>(30);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // State for analytics data
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [hostsData, setHostsData] = useState<TimeSeriesDataPoint[]>([]);
  const [vulnData, setVulnData] = useState<VulnerabilityTimeSeriesDataPoint[]>(
    []
  );
  const [servicesData, setServicesData] = useState<ServiceCount[]>([]);
  const [frequencyData, setFrequencyData] = useState<TimeSeriesDataPoint[]>([]);

  useEffect(() => {
    loadAnalyticsData();
  }, [dateRange]);

  const loadAnalyticsData = async () => {
    setLoading(true);
    setError(null);

    try {
      const [summaryRes, hostsRes, vulnRes, servicesRes, frequencyRes] =
        await Promise.all([
          analyticsAPI.getSummary(dateRange),
          analyticsAPI.getHosts(dateRange),
          analyticsAPI.getVulnerabilities(dateRange),
          analyticsAPI.getServices(10),
          analyticsAPI.getFrequency(dateRange),
        ]);

      setSummary(summaryRes.data);
      setHostsData(hostsRes.data);
      setVulnData(vulnRes.data);
      setServicesData(servicesRes.data);
      setFrequencyData(frequencyRes.data);
    } catch (err: any) {
      console.error('Failed to load analytics:', err);
      setError(err.response?.data?.message || 'Failed to load analytics data');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (error) {
    return (
      <Card className="p-6">
        <div className="text-center">
          <AlertTriangle className="h-12 w-12 text-yellow-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">
            Failed to Load Analytics
          </h3>
          <p className="text-slate-400 mb-4">{error}</p>
          <button
            onClick={loadAnalyticsData}
            className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/80 transition-colors"
          >
            Retry
          </button>
        </div>
      </Card>
    );
  }

  if (!summary) {
    return null;
  }

  return (
    <div className="space-y-6">
      {/* Header with Date Range Selector */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white mb-1">
            Analytics Dashboard
          </h2>
          <p className="text-slate-400">
            Insights and trends from your security scans
          </p>
        </div>
        <div className="flex items-center gap-2 bg-dark-surface border border-dark-border rounded-lg p-1">
          <button
            onClick={() => setDateRange(7)}
            className={`flex items-center gap-2 px-3 py-2 rounded transition-colors ${
              dateRange === 7
                ? 'bg-primary text-white'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Calendar className="h-4 w-4" />
            7 Days
          </button>
          <button
            onClick={() => setDateRange(30)}
            className={`flex items-center gap-2 px-3 py-2 rounded transition-colors ${
              dateRange === 30
                ? 'bg-primary text-white'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Calendar className="h-4 w-4" />
            30 Days
          </button>
          <button
            onClick={() => setDateRange(90)}
            className={`flex items-center gap-2 px-3 py-2 rounded transition-colors ${
              dateRange === 90
                ? 'bg-primary text-white'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Calendar className="h-4 w-4" />
            90 Days
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={summary.total_scans}
          subtitle={`${summary.scans_this_week} this week`}
          icon={<Activity className="h-6 w-6 text-primary" />}
          color="text-primary"
        />
        <StatCard
          title="Hosts Discovered"
          value={summary.total_hosts}
          subtitle={`${summary.total_ports} open ports`}
          icon={<Server className="h-6 w-6 text-blue-400" />}
          color="text-blue-400"
        />
        <StatCard
          title="Total Vulnerabilities"
          value={summary.total_vulnerabilities}
          subtitle={`${summary.critical_vulns} critical`}
          icon={<AlertTriangle className="h-6 w-6 text-yellow-400" />}
          color="text-yellow-400"
        />
        <StatCard
          title="Critical Findings"
          value={summary.critical_vulns}
          subtitle="Requires immediate attention"
          icon={<Shield className="h-6 w-6 text-severity-critical" />}
          color="text-severity-critical"
        />
      </div>

      {/* Vulnerability Breakdown */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold text-white mb-4">
          Vulnerability Severity Breakdown
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-dark-bg p-4 rounded-lg border border-dark-border">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">Critical</span>
              <Shield className="h-4 w-4 text-severity-critical" />
            </div>
            <p className="text-2xl font-bold text-severity-critical">
              {summary.critical_vulns}
            </p>
          </div>
          <div className="bg-dark-bg p-4 rounded-lg border border-dark-border">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">High</span>
              <Shield className="h-4 w-4 text-severity-high" />
            </div>
            <p className="text-2xl font-bold text-severity-high">
              {summary.high_vulns}
            </p>
          </div>
          <div className="bg-dark-bg p-4 rounded-lg border border-dark-border">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">Medium</span>
              <Shield className="h-4 w-4 text-severity-medium" />
            </div>
            <p className="text-2xl font-bold text-severity-medium">
              {summary.medium_vulns}
            </p>
          </div>
          <div className="bg-dark-bg p-4 rounded-lg border border-dark-border">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">Low</span>
              <Shield className="h-4 w-4 text-severity-low" />
            </div>
            <p className="text-2xl font-bold text-severity-low">
              {summary.low_vulns}
            </p>
          </div>
        </div>
      </Card>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Hosts Over Time */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold text-white mb-4">
            Hosts Discovered Over Time
          </h3>
          {hostsData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={hostsData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  dataKey="date"
                  tickFormatter={formatDate}
                  stroke="#94a3b8"
                  style={{ fontSize: '12px' }}
                />
                <YAxis stroke="#94a3b8" style={{ fontSize: '12px' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#fff',
                  }}
                  labelFormatter={formatDate}
                />
                <Line
                  type="monotone"
                  dataKey="value"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  dot={{ fill: '#3b82f6', r: 4 }}
                  activeDot={{ r: 6 }}
                  name="Hosts"
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-64 text-slate-400">
              <p>No data available</p>
            </div>
          )}
        </Card>

        {/* Scan Frequency */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold text-white mb-4">
            Scan Frequency
          </h3>
          {frequencyData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={frequencyData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  dataKey="date"
                  tickFormatter={formatDate}
                  stroke="#94a3b8"
                  style={{ fontSize: '12px' }}
                />
                <YAxis stroke="#94a3b8" style={{ fontSize: '12px' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#fff',
                  }}
                  labelFormatter={formatDate}
                />
                <Line
                  type="monotone"
                  dataKey="value"
                  stroke="#8b5cf6"
                  strokeWidth={2}
                  dot={{ fill: '#8b5cf6', r: 4 }}
                  activeDot={{ r: 6 }}
                  name="Scans"
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-64 text-slate-400">
              <p>No data available</p>
            </div>
          )}
        </Card>

        {/* Vulnerability Trends */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold text-white mb-4">
            Vulnerability Trends by Severity
          </h3>
          {vulnData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={vulnData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  dataKey="date"
                  tickFormatter={formatDate}
                  stroke="#94a3b8"
                  style={{ fontSize: '12px' }}
                />
                <YAxis stroke="#94a3b8" style={{ fontSize: '12px' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#fff',
                  }}
                  labelFormatter={formatDate}
                />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  iconType="circle"
                  wrapperStyle={{ fontSize: '12px', color: '#cbd5e1' }}
                />
                <Area
                  type="monotone"
                  dataKey="critical"
                  stackId="1"
                  stroke="#ef4444"
                  fill="#ef4444"
                  fillOpacity={0.6}
                  name="Critical"
                />
                <Area
                  type="monotone"
                  dataKey="high"
                  stackId="1"
                  stroke="#f97316"
                  fill="#f97316"
                  fillOpacity={0.6}
                  name="High"
                />
                <Area
                  type="monotone"
                  dataKey="medium"
                  stackId="1"
                  stroke="#eab308"
                  fill="#eab308"
                  fillOpacity={0.6}
                  name="Medium"
                />
                <Area
                  type="monotone"
                  dataKey="low"
                  stackId="1"
                  stroke="#3b82f6"
                  fill="#3b82f6"
                  fillOpacity={0.6}
                  name="Low"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-64 text-slate-400">
              <p>No data available</p>
            </div>
          )}
        </Card>

        {/* Top Services */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold text-white mb-4">
            Top Services Discovered
          </h3>
          {servicesData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={servicesData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis type="number" stroke="#94a3b8" style={{ fontSize: '12px' }} />
                <YAxis
                  dataKey="service"
                  type="category"
                  stroke="#94a3b8"
                  style={{ fontSize: '12px' }}
                  width={100}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#fff',
                  }}
                />
                <Bar
                  dataKey="count"
                  fill="#06b6d4"
                  radius={[0, 4, 4, 0]}
                  name="Count"
                />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-64 text-slate-400">
              <p>No data available</p>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};

export default AnalyticsDashboard;
