import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../../components/layout/Layout';
import { crmAPI } from '../../services/api';
import type { CrmDashboardStats, EngagementMilestone, Communication } from '../../types';

export default function CrmDashboard() {
  const [stats, setStats] = useState<CrmDashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      setLoading(true);
      const response = await crmAPI.getDashboard();
      setStats(response.data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load dashboard';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleDateString();
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
    }).format(value);
  };

  const getMilestoneStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'in_progress':
        return 'bg-blue-100 text-blue-800';
      case 'overdue':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getCommTypeIcon = (type: string) => {
    switch (type) {
      case 'email':
        return '📧';
      case 'call':
        return '📞';
      case 'meeting':
        return '🤝';
      case 'note':
        return '📝';
      default:
        return '💬';
    }
  };

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
        </div>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout>
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-800">{error}</p>
          <button onClick={loadDashboard} className="mt-2 text-red-600 hover:text-red-800">
            Try Again
          </button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">CRM Dashboard</h1>
        <Link
          to="/crm/customers"
          className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700"
        >
          + New Customer
        </Link>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-indigo-100 text-indigo-600">
              <svg className="h-8 w-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Total Customers</p>
              <p className="text-2xl font-semibold text-gray-900">{stats?.total_customers || 0}</p>
              <p className="text-sm text-green-600">{stats?.active_customers || 0} active</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-green-100 text-green-600">
              <svg className="h-8 w-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Engagements</p>
              <p className="text-2xl font-semibold text-gray-900">{stats?.total_engagements || 0}</p>
              <p className="text-sm text-blue-600">{stats?.active_engagements || 0} in progress</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-yellow-100 text-yellow-600">
              <svg className="h-8 w-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Contract Value</p>
              <p className="text-2xl font-semibold text-gray-900">
                {formatCurrency(stats?.total_contracts_value || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-purple-100 text-purple-600">
              <svg className="h-8 w-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Upcoming Milestones</p>
              <p className="text-2xl font-semibold text-gray-900">
                {stats?.upcoming_milestones?.length || 0}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Link
          to="/crm/customers"
          className="bg-white rounded-lg shadow p-4 hover:shadow-md transition-shadow flex items-center space-x-3"
        >
          <span className="text-2xl">👥</span>
          <span className="font-medium text-gray-700">View Customers</span>
        </Link>
        <Link
          to="/crm/engagements"
          className="bg-white rounded-lg shadow p-4 hover:shadow-md transition-shadow flex items-center space-x-3"
        >
          <span className="text-2xl">📋</span>
          <span className="font-medium text-gray-700">View Engagements</span>
        </Link>
        <Link
          to="/crm/contracts"
          className="bg-white rounded-lg shadow p-4 hover:shadow-md transition-shadow flex items-center space-x-3"
        >
          <span className="text-2xl">📄</span>
          <span className="font-medium text-gray-700">View Contracts</span>
        </Link>
        <Link
          to="/crm/time-tracking"
          className="bg-white rounded-lg shadow p-4 hover:shadow-md transition-shadow flex items-center space-x-3"
        >
          <span className="text-2xl">⏱️</span>
          <span className="font-medium text-gray-700">Time Tracking</span>
        </Link>
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Upcoming Milestones */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-medium text-gray-900">Upcoming Milestones</h2>
          </div>
          <div className="divide-y divide-gray-200">
            {stats?.upcoming_milestones && stats.upcoming_milestones.length > 0 ? (
              stats.upcoming_milestones.slice(0, 5).map((milestone: EngagementMilestone) => (
                <div key={milestone.id} className="px-6 py-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-medium text-gray-900">{milestone.name}</p>
                      <p className="text-sm text-gray-500">
                        Due: {formatDate(milestone.due_date)}
                      </p>
                    </div>
                    <span
                      className={`px-2 py-1 text-xs rounded-full ${getMilestoneStatusColor(
                        milestone.status
                      )}`}
                    >
                      {milestone.status}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="px-6 py-8 text-center text-gray-500">
                No upcoming milestones
              </div>
            )}
          </div>
        </div>

        {/* Recent Communications */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-medium text-gray-900">Recent Activity</h2>
          </div>
          <div className="divide-y divide-gray-200">
            {stats?.recent_communications && stats.recent_communications.length > 0 ? (
              stats.recent_communications.slice(0, 5).map((comm: Communication) => (
                <div key={comm.id} className="px-6 py-4">
                  <div className="flex items-start space-x-3">
                    <span className="text-xl">{getCommTypeIcon(comm.comm_type)}</span>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-gray-900 truncate">
                        {comm.subject || `${comm.comm_type} logged`}
                      </p>
                      <p className="text-sm text-gray-500">
                        {formatDate(comm.comm_date)}
                      </p>
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="px-6 py-8 text-center text-gray-500">
                No recent activity
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
    </Layout>
  );
}
