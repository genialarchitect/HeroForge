import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { adminAPI } from '../../services/api';
import {
  Shield,
  AlertTriangle,
  Activity,
  Users,
  Clock,
  RefreshCw,
  ShieldAlert,
  TrendingUp,
  Globe,
} from 'lucide-react';
import { format, formatDistanceToNow } from 'date-fns';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  BarChart,
  Bar,
} from 'recharts';
import type {
  RateLimitDashboardData,
  RateLimitConfig,
  RateLimitEvent,
  IpStats,
} from '../../types';

const RateLimitDashboard: React.FC = () => {
  const {
    data: dashboardData,
    isLoading,
    error,
    refetch,
  } = useQuery<RateLimitDashboardData>({
    queryKey: ['rateLimitDashboard'],
    queryFn: async () => {
      const response = await adminAPI.getRateLimitDashboard();
      return response.data;
    },
    refetchInterval: 30000, // Auto-refresh every 30 seconds
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-2 text-slate-400">
          <RefreshCw className="h-5 w-5 animate-spin" />
          <span>Loading rate limit data...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-400">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-5 w-5" />
          <span>Failed to load rate limit data</span>
        </div>
      </div>
    );
  }

  if (!dashboardData) {
    return null;
  }

  const { configs, summary, recent_events, top_ips, requests_over_time } = dashboardData;

  // Format time series data for chart
  const chartData = requests_over_time.map((point) => ({
    time: format(new Date(point.timestamp), 'HH:mm'),
    total: point.total_requests,
    blocked: point.blocked_requests,
  }));

  // Category data for bar chart
  const categoryData = Object.entries(summary.requests_by_category).map(([category, count]) => ({
    category: category.charAt(0).toUpperCase() + category.slice(1),
    requests: count,
    blocked: summary.blocked_by_category[category] || 0,
  }));

  return (
    <div className="space-y-6">
      {/* Header with refresh button and live indicator */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert className="h-5 w-5 text-primary" />
          <h3 className="text-lg font-semibold text-white">Rate Limit Dashboard</h3>
          <span className="flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium text-green-400 bg-green-500/10 border border-green-500/30 rounded-full">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
            </span>
            Live
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500">Auto-refresh: 30s</span>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-3 py-1.5 text-sm text-slate-400 hover:text-white
                       bg-dark-card border border-dark-border rounded-lg transition-colors hover:border-primary/50"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard
          icon={Activity}
          label="Total Requests (24h)"
          value={summary.total_requests_24h.toLocaleString()}
          color="text-cyan-400"
        />
        <StatCard
          icon={ShieldAlert}
          label="Blocked Requests (24h)"
          value={summary.blocked_requests_24h.toLocaleString()}
          color="text-red-400"
        />
        <StatCard
          icon={TrendingUp}
          label="Block Rate"
          value={`${summary.block_rate_percent.toFixed(2)}%`}
          color={summary.block_rate_percent > 5 ? 'text-yellow-400' : 'text-green-400'}
        />
        <StatCard
          icon={Users}
          label="Unique IPs (24h)"
          value={summary.unique_ips_24h.toLocaleString()}
          color="text-purple-400"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Requests Over Time Chart */}
        <div className="bg-dark-card border border-dark-border rounded-lg p-4">
          <h4 className="text-sm font-medium text-slate-400 mb-4">Requests Over Time (24h)</h4>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis
                  dataKey="time"
                  stroke="#9ca3af"
                  fontSize={12}
                  tickLine={false}
                />
                <YAxis stroke="#9ca3af" fontSize={12} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1f2937',
                    border: '1px solid #374151',
                    borderRadius: '8px',
                  }}
                  labelStyle={{ color: '#fff' }}
                />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="total"
                  name="Total Requests"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="blocked"
                  name="Blocked"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Requests by Category Chart */}
        <div className="bg-dark-card border border-dark-border rounded-lg p-4">
          <h4 className="text-sm font-medium text-slate-400 mb-4">Requests by Category</h4>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis
                  dataKey="category"
                  stroke="#9ca3af"
                  fontSize={12}
                  tickLine={false}
                />
                <YAxis stroke="#9ca3af" fontSize={12} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1f2937',
                    border: '1px solid #374151',
                    borderRadius: '8px',
                  }}
                  labelStyle={{ color: '#fff' }}
                />
                <Legend />
                <Bar dataKey="requests" name="Total Requests" fill="#06b6d4" />
                <Bar dataKey="blocked" name="Blocked" fill="#ef4444" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Rate Limit Configurations */}
      <div className="bg-dark-card border border-dark-border rounded-lg p-4">
        <h4 className="text-sm font-medium text-slate-400 mb-4 flex items-center gap-2">
          <Shield className="h-4 w-4" />
          Rate Limit Rules
        </h4>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-dark-border">
                <th className="px-4 py-2 text-left text-slate-400 font-medium">Category</th>
                <th className="px-4 py-2 text-left text-slate-400 font-medium">Limit</th>
                <th className="px-4 py-2 text-left text-slate-400 font-medium">Burst Size</th>
                <th className="px-4 py-2 text-left text-slate-400 font-medium">Description</th>
              </tr>
            </thead>
            <tbody>
              {configs.map((config: RateLimitConfig) => (
                <tr
                  key={config.category}
                  className="border-b border-dark-border/50 hover:bg-dark-bg/50"
                >
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-2">
                      <CategoryBadge category={config.category} />
                      <span className="text-white font-medium">{config.name}</span>
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    {config.requests_per_period} / {config.period}
                  </td>
                  <td className="px-4 py-3 text-slate-300">{config.burst_size}</td>
                  <td className="px-4 py-3 text-slate-400">{config.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom Row: Recent Events and Top IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Rate Limit Events */}
        <div className="bg-dark-card border border-dark-border rounded-lg p-4">
          <h4 className="text-sm font-medium text-slate-400 mb-4 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            Recent Blocked Requests
          </h4>
          {recent_events.length === 0 ? (
            <div className="text-center py-8 text-slate-500">
              <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No blocked requests in the last 24 hours</p>
            </div>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {recent_events.slice(0, 20).map((event: RateLimitEvent) => (
                <div
                  key={event.id}
                  className="flex items-center justify-between p-2 bg-dark-bg rounded border border-dark-border/50"
                >
                  <div className="flex items-center gap-3">
                    <CategoryBadge category={event.category} size="sm" />
                    <div>
                      <div className="flex items-center gap-2">
                        <Globe className="h-3 w-3 text-slate-500" />
                        <span className="text-white font-mono text-sm">{event.ip}</span>
                      </div>
                      <div className="text-xs text-slate-500 truncate max-w-[200px]">
                        {event.endpoint}
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-slate-400 flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top IPs */}
        <div className="bg-dark-card border border-dark-border rounded-lg p-4">
          <h4 className="text-sm font-medium text-slate-400 mb-4 flex items-center gap-2">
            <Users className="h-4 w-4" />
            Top Requesting IPs (24h)
          </h4>
          {top_ips.length === 0 ? (
            <div className="text-center py-8 text-slate-500">
              <Globe className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No request data available</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-dark-border">
                    <th className="px-3 py-2 text-left text-slate-400 font-medium">IP Address</th>
                    <th className="px-3 py-2 text-right text-slate-400 font-medium">Requests</th>
                    <th className="px-3 py-2 text-right text-slate-400 font-medium">Blocked</th>
                    <th className="px-3 py-2 text-right text-slate-400 font-medium">Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {top_ips.slice(0, 10).map((ip: IpStats) => (
                    <tr
                      key={ip.ip}
                      className="border-b border-dark-border/50 hover:bg-dark-bg/50"
                    >
                      <td className="px-3 py-2">
                        <span className="font-mono text-white">{ip.ip}</span>
                      </td>
                      <td className="px-3 py-2 text-right text-slate-300">
                        {ip.total_requests.toLocaleString()}
                      </td>
                      <td className="px-3 py-2 text-right">
                        <span
                          className={
                            ip.blocked_requests > 0 ? 'text-red-400' : 'text-slate-500'
                          }
                        >
                          {ip.blocked_requests.toLocaleString()}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-right text-slate-400 text-xs">
                        {formatDistanceToNow(new Date(ip.last_seen), { addSuffix: true })}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Helper Components

interface StatCardProps {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  color: string;
}

const StatCard: React.FC<StatCardProps> = ({ icon: Icon, label, value, color }) => (
  <div className="bg-dark-card border border-dark-border rounded-lg p-4">
    <div className="flex items-center gap-3">
      <div className={`p-2 rounded-lg bg-dark-bg ${color}`}>
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <p className="text-sm text-slate-400">{label}</p>
        <p className={`text-xl font-bold ${color}`}>{value}</p>
      </div>
    </div>
  </div>
);

interface CategoryBadgeProps {
  category: string;
  size?: 'sm' | 'md';
}

const CategoryBadge: React.FC<CategoryBadgeProps> = ({ category, size = 'md' }) => {
  const colors: Record<string, string> = {
    auth: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    api: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
    scan: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  };

  const sizeClasses = size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center rounded border font-medium uppercase ${
        colors[category] || 'bg-slate-500/20 text-slate-400 border-slate-500/30'
      } ${sizeClasses}`}
    >
      {category}
    </span>
  );
};

export default RateLimitDashboard;
