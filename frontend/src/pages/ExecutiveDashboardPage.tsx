import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/layout/Layout';
import { executiveAnalyticsAPI, crmAPI } from '../services/api';
import type {
  ExecutiveDashboard,
  ExecutiveSummary,
  CustomerSecurityTrends,
  RemediationVelocity,
  RiskTrendPoint,
  MethodologyExecutiveCoverage,
} from '../types';
import { toast } from 'react-toastify';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import {
  TrendingUp,
  TrendingDown,
  Minus,
  Activity,
  Shield,
  Clock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  BarChart3,
  Target,
  Users,
  FileText,
  Building2,
} from 'lucide-react';

interface Customer {
  id: string;
  name: string;
}

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const ExecutiveDashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(true);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [selectedCustomerId, setSelectedCustomerId] = useState<string>('');
  const [months, setMonths] = useState(6);
  const [dashboard, setDashboard] = useState<ExecutiveDashboard | null>(null);

  // Load customers on mount
  useEffect(() => {
    loadCustomers();
    loadDashboard();
  }, []);

  // Reload dashboard when customer or months changes
  useEffect(() => {
    loadDashboard();
  }, [selectedCustomerId, months]);

  const loadCustomers = async () => {
    try {
      const response = await crmAPI.customers.getAll();
      setCustomers(response.data);
    } catch (error) {
      console.error('Failed to load customers:', error);
    }
  };

  const loadDashboard = async () => {
    setIsLoading(true);
    try {
      const response = await executiveAnalyticsAPI.getExecutiveDashboard(
        selectedCustomerId || undefined,
        months
      );
      setDashboard(response.data);
    } catch (error) {
      console.error('Failed to load dashboard:', error);
      toast.error('Failed to load executive dashboard');
    } finally {
      setIsLoading(false);
    }
  };

  const getTrendIcon = (direction: string) => {
    switch (direction) {
      case 'Improving':
        return <TrendingDown className="h-5 w-5 text-green-400" />;
      case 'Declining':
        return <TrendingUp className="h-5 w-5 text-red-400" />;
      default:
        return <Minus className="h-5 w-5 text-yellow-400" />;
    }
  };

  const getRiskRatingColor = (rating: string) => {
    switch (rating) {
      case 'Critical':
        return 'text-red-400 bg-red-500/20';
      case 'High':
        return 'text-orange-400 bg-orange-500/20';
      case 'Medium':
        return 'text-yellow-400 bg-yellow-500/20';
      default:
        return 'text-green-400 bg-green-500/20';
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <BarChart3 className="h-6 w-6 text-primary" />
              <h1 className="text-2xl font-bold text-white">
                Executive Dashboard
              </h1>
            </div>
            <p className="text-slate-400">
              Security posture trends, remediation metrics, and testing coverage
            </p>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-4">
            <select
              value={selectedCustomerId}
              onChange={(e) => setSelectedCustomerId(e.target.value)}
              className="px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary"
            >
              <option value="">All Customers</option>
              {customers.map((customer) => (
                <option key={customer.id} value={customer.id}>
                  {customer.name}
                </option>
              ))}
            </select>

            <select
              value={months}
              onChange={(e) => setMonths(Number(e.target.value))}
              className="px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary"
            >
              <option value={3}>Last 3 Months</option>
              <option value={6}>Last 6 Months</option>
              <option value={12}>Last 12 Months</option>
            </select>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          </div>
        ) : dashboard ? (
          <div className="space-y-6">
            {/* Executive Summary Cards */}
            {dashboard.summary && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* Risk Rating */}
                <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-slate-400 text-sm">Risk Rating</span>
                    <Shield className="h-5 w-5 text-primary" />
                  </div>
                  <div className="flex items-center gap-3">
                    <span
                      className={`text-2xl font-bold px-3 py-1 rounded ${getRiskRatingColor(
                        dashboard.summary.risk_rating
                      )}`}
                    >
                      {dashboard.summary.risk_rating}
                    </span>
                    {getTrendIcon(dashboard.summary.trend_direction)}
                  </div>
                  <p className="text-xs text-slate-500 mt-2">
                    {dashboard.summary.trend_direction}
                  </p>
                </div>

                {/* Open Vulnerabilities */}
                <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-slate-400 text-sm">
                      Open Vulnerabilities
                    </span>
                    <AlertTriangle className="h-5 w-5 text-yellow-400" />
                  </div>
                  <div className="text-3xl font-bold text-white">
                    {dashboard.summary.open_vulnerabilities}
                  </div>
                  <div className="flex items-center gap-3 mt-2 text-xs">
                    <span className="text-red-400">
                      {dashboard.summary.critical_open} Critical
                    </span>
                    <span className="text-orange-400">
                      {dashboard.summary.high_open} High
                    </span>
                  </div>
                </div>

                {/* Avg Remediation Time */}
                <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-slate-400 text-sm">
                      Avg Remediation
                    </span>
                    <Clock className="h-5 w-5 text-cyan-400" />
                  </div>
                  <div className="text-3xl font-bold text-white">
                    {dashboard.summary.avg_remediation_days.toFixed(1)}
                    <span className="text-lg text-slate-400 ml-1">days</span>
                  </div>
                  <p className="text-xs text-slate-500 mt-2">
                    Time to resolve issues
                  </p>
                </div>

                {/* Engagements */}
                <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-slate-400 text-sm">Engagements</span>
                    <Building2 className="h-5 w-5 text-purple-400" />
                  </div>
                  <div className="text-3xl font-bold text-white">
                    {dashboard.summary.active_engagements}
                    <span className="text-lg text-slate-400 ml-1">
                      / {dashboard.summary.total_engagements}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-2">Active / Total</p>
                </div>
              </div>
            )}

            {/* Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Risk Trends Chart */}
              {dashboard.risk_trends.length > 0 && (
                <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <Activity className="h-5 w-5 text-primary" />
                    Risk Score Trend
                  </h3>
                  <ResponsiveContainer width="100%" height={250}>
                    <AreaChart data={dashboard.risk_trends}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis
                        dataKey="date"
                        tick={{ fill: '#94a3b8', fontSize: 12 }}
                        tickFormatter={(value) =>
                          new Date(value).toLocaleDateString('en-US', {
                            month: 'short',
                            day: 'numeric',
                          })
                        }
                      />
                      <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1f2937',
                          border: '1px solid #374151',
                          borderRadius: '8px',
                        }}
                      />
                      <Area
                        type="monotone"
                        dataKey="risk_score"
                        stroke="#06b6d4"
                        fill="#06b6d4"
                        fillOpacity={0.2}
                        name="Risk Score"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* Remediation Velocity Chart */}
              {dashboard.remediation_velocity &&
                dashboard.remediation_velocity.velocity_trend.length > 0 && (
                  <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                      <TrendingDown className="h-5 w-5 text-green-400" />
                      Remediation Velocity
                    </h3>
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart
                        data={dashboard.remediation_velocity.velocity_trend}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis
                          dataKey="week"
                          tick={{ fill: '#94a3b8', fontSize: 12 }}
                        />
                        <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1f2937',
                            border: '1px solid #374151',
                            borderRadius: '8px',
                          }}
                        />
                        <Bar
                          dataKey="resolved_count"
                          fill="#22c55e"
                          name="Resolved"
                          radius={[4, 4, 0, 0]}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
            </div>

            {/* Security Trends Chart (if customer selected) */}
            {dashboard.security_trends &&
              dashboard.security_trends.months.length > 0 && (
                <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                      <Shield className="h-5 w-5 text-primary" />
                      Security Posture - {dashboard.security_trends.customer_name}
                    </h3>
                    {dashboard.security_trends.improvement_percent !== 0 && (
                      <span
                        className={`px-3 py-1 rounded text-sm font-medium ${
                          dashboard.security_trends.improvement_percent > 0
                            ? 'bg-green-500/20 text-green-400'
                            : 'bg-red-500/20 text-red-400'
                        }`}
                      >
                        {dashboard.security_trends.improvement_percent > 0
                          ? '+'
                          : ''}
                        {dashboard.security_trends.improvement_percent.toFixed(1)}%
                      </span>
                    )}
                  </div>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={dashboard.security_trends.months}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis
                        dataKey="month"
                        tick={{ fill: '#94a3b8', fontSize: 12 }}
                      />
                      <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1f2937',
                          border: '1px solid #374151',
                          borderRadius: '8px',
                        }}
                      />
                      <Legend />
                      <Line
                        type="monotone"
                        dataKey="critical"
                        stroke={SEVERITY_COLORS.critical}
                        name="Critical"
                        strokeWidth={2}
                      />
                      <Line
                        type="monotone"
                        dataKey="high"
                        stroke={SEVERITY_COLORS.high}
                        name="High"
                        strokeWidth={2}
                      />
                      <Line
                        type="monotone"
                        dataKey="medium"
                        stroke={SEVERITY_COLORS.medium}
                        name="Medium"
                        strokeWidth={2}
                      />
                      <Line
                        type="monotone"
                        dataKey="resolved"
                        stroke="#22c55e"
                        name="Resolved"
                        strokeWidth={2}
                        strokeDasharray="5 5"
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}

            {/* Bottom Row - Remediation Stats + Methodology Coverage */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Remediation Stats */}
              {dashboard.remediation_velocity && (
                <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <Clock className="h-5 w-5 text-cyan-400" />
                    Remediation by Severity
                  </h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-3 bg-dark-hover rounded-lg">
                      <div className="text-xs text-red-400 mb-1">Critical</div>
                      <div className="text-xl font-bold text-white">
                        {dashboard.remediation_velocity.avg_days_critical.toFixed(
                          1
                        )}
                        <span className="text-sm text-slate-400 ml-1">
                          days
                        </span>
                      </div>
                    </div>
                    <div className="p-3 bg-dark-hover rounded-lg">
                      <div className="text-xs text-orange-400 mb-1">High</div>
                      <div className="text-xl font-bold text-white">
                        {dashboard.remediation_velocity.avg_days_high.toFixed(
                          1
                        )}
                        <span className="text-sm text-slate-400 ml-1">
                          days
                        </span>
                      </div>
                    </div>
                    <div className="p-3 bg-dark-hover rounded-lg">
                      <div className="text-xs text-yellow-400 mb-1">Medium</div>
                      <div className="text-xl font-bold text-white">
                        {dashboard.remediation_velocity.avg_days_medium.toFixed(
                          1
                        )}
                        <span className="text-sm text-slate-400 ml-1">
                          days
                        </span>
                      </div>
                    </div>
                    <div className="p-3 bg-dark-hover rounded-lg">
                      <div className="text-xs text-green-400 mb-1">Low</div>
                      <div className="text-xl font-bold text-white">
                        {dashboard.remediation_velocity.avg_days_low.toFixed(1)}
                        <span className="text-sm text-slate-400 ml-1">
                          days
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="mt-4 pt-4 border-t border-dark-border">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 text-sm">
                        Remediation Rate
                      </span>
                      <span className="text-lg font-bold text-green-400">
                        {dashboard.remediation_velocity.remediation_rate.toFixed(
                          1
                        )}
                        %
                      </span>
                    </div>
                    <div className="mt-2 h-2 bg-dark-hover rounded-full overflow-hidden">
                      <div
                        className="h-full bg-green-500 rounded-full transition-all"
                        style={{
                          width: `${Math.min(
                            dashboard.remediation_velocity.remediation_rate,
                            100
                          )}%`,
                        }}
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* Methodology Coverage */}
              {dashboard.methodology_coverage && (
                <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <Target className="h-5 w-5 text-purple-400" />
                    Testing Coverage
                  </h3>
                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div className="p-3 bg-dark-hover rounded-lg text-center">
                      <div className="text-2xl font-bold text-white">
                        {dashboard.methodology_coverage.completed_checklists}
                        <span className="text-lg text-slate-400 mx-1">/</span>
                        {dashboard.methodology_coverage.total_checklists}
                      </div>
                      <div className="text-xs text-slate-400">
                        Checklists Completed
                      </div>
                    </div>
                    <div className="p-3 bg-dark-hover rounded-lg text-center">
                      <div className="text-2xl font-bold text-white">
                        {dashboard.methodology_coverage.total_items_tested}
                      </div>
                      <div className="text-xs text-slate-400">Items Tested</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="flex items-center gap-2">
                        <CheckCircle2 className="h-4 w-4 text-green-400" />
                        Passed
                      </span>
                      <span className="text-green-400">
                        {dashboard.methodology_coverage.passed_items}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="flex items-center gap-2">
                        <XCircle className="h-4 w-4 text-red-400" />
                        Failed
                      </span>
                      <span className="text-red-400">
                        {dashboard.methodology_coverage.failed_items}
                      </span>
                    </div>
                  </div>

                  {dashboard.methodology_coverage.coverage_by_framework.length >
                    0 && (
                    <div className="mt-4 pt-4 border-t border-dark-border">
                      <div className="text-sm text-slate-400 mb-2">
                        By Framework
                      </div>
                      <div className="space-y-2">
                        {dashboard.methodology_coverage.coverage_by_framework.map(
                          (fw) => (
                            <div key={fw.framework_name} className="space-y-1">
                              <div className="flex items-center justify-between text-sm">
                                <span className="text-white">
                                  {fw.framework_name}
                                </span>
                                <span className="text-slate-400">
                                  {fw.coverage_percent.toFixed(0)}%
                                </span>
                              </div>
                              <div className="h-1.5 bg-dark-hover rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-primary rounded-full transition-all"
                                  style={{ width: `${fw.coverage_percent}%` }}
                                />
                              </div>
                            </div>
                          )
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Empty State */}
            {!dashboard.summary &&
              dashboard.risk_trends.length === 0 &&
              !dashboard.remediation_velocity &&
              !dashboard.methodology_coverage && (
                <div className="bg-dark-surface rounded-lg border border-dark-border p-8 text-center">
                  <BarChart3 className="h-12 w-12 text-slate-500 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-white mb-2">
                    No Analytics Data
                  </h3>
                  <p className="text-slate-400 mb-4">
                    Start scanning and tracking vulnerabilities to see analytics
                    here.
                  </p>
                  <button
                    onClick={() => navigate('/dashboard')}
                    className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors"
                  >
                    Go to Scans
                  </button>
                </div>
              )}
          </div>
        ) : (
          <div className="bg-dark-surface rounded-lg border border-dark-border p-8 text-center">
            <BarChart3 className="h-12 w-12 text-slate-500 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">
              Failed to Load Dashboard
            </h3>
            <p className="text-slate-400">
              Please try refreshing the page or check your connection.
            </p>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default ExecutiveDashboardPage;
