import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { PortalLayout } from '../../components/portal/PortalLayout';
import { portalDashboardAPI } from '../../services/portalApi';
import type { PortalDashboardStats } from '../../types';

// Inline SVG icons to avoid heroicons dependency
const FolderIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
  </svg>
);

const ShieldExclamationIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z" />
  </svg>
);

const DocumentTextIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
  </svg>
);

const ExclamationTriangleIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
  </svg>
);

const ClockIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const CalendarIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6.75 3v2.25M17.25 3v2.25M3 18.75V7.5a2.25 2.25 0 012.25-2.25h13.5A2.25 2.25 0 0121 7.5v11.25m-18 0A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75m-18 0v-7.5A2.25 2.25 0 015.25 9h13.5A2.25 2.25 0 0121 11.25v7.5" />
  </svg>
);

export function PortalDashboard() {
  const [stats, setStats] = useState<PortalDashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        const response = await portalDashboardAPI.getDashboard();
        setStats(response.data);
      } catch (err) {
        console.error('Failed to fetch dashboard:', err);
        setError('Failed to load dashboard data');
      } finally {
        setLoading(false);
      }
    };

    fetchDashboard();
  }, []);

  if (loading) {
    return (
      <PortalLayout>
        <div className="flex h-64 items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-blue-600 border-t-transparent"></div>
        </div>
      </PortalLayout>
    );
  }

  if (error || !stats) {
    return (
      <PortalLayout>
        <div className="rounded-lg bg-red-50 p-4 text-red-700">
          {error || 'Failed to load dashboard'}
        </div>
      </PortalLayout>
    );
  }

  const statCards = [
    {
      name: 'Active Engagements',
      value: stats.active_engagements,
      total: stats.total_engagements,
      icon: FolderIcon,
      color: 'text-blue-600 bg-blue-100',
      href: '/portal/engagements',
    },
    {
      name: 'Open Vulnerabilities',
      value: stats.open_vulnerabilities,
      subtext: `${stats.critical_vulnerabilities} critical, ${stats.high_vulnerabilities} high`,
      icon: ShieldExclamationIcon,
      color: stats.critical_vulnerabilities > 0 ? 'text-red-600 bg-red-100' : 'text-yellow-600 bg-yellow-100',
      href: '/portal/vulnerabilities',
    },
    {
      name: 'Available Reports',
      value: stats.available_reports,
      icon: DocumentTextIcon,
      color: 'text-green-600 bg-green-100',
      href: '/portal/reports',
    },
  ];

  return (
    <PortalLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-gray-900">
            Welcome back, {stats.customer_name}
          </h1>
          <p className="mt-1 text-sm text-gray-500">
            Here's an overview of your security posture
          </p>
        </div>

        {/* Critical Alert Banner */}
        {stats.critical_vulnerabilities > 0 && (
          <div className="rounded-lg bg-red-50 border border-red-200 p-4">
            <div className="flex items-center">
              <ExclamationTriangleIcon className="h-6 w-6 text-red-600 mr-3" />
              <div>
                <h3 className="text-sm font-medium text-red-800">
                  Critical Vulnerabilities Detected
                </h3>
                <p className="text-sm text-red-700 mt-1">
                  You have {stats.critical_vulnerabilities} critical vulnerabilit{stats.critical_vulnerabilities === 1 ? 'y' : 'ies'} that require immediate attention.
                </p>
              </div>
              <Link
                to="/portal/vulnerabilities?severity=critical"
                className="ml-auto rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700"
              >
                View Details
              </Link>
            </div>
          </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {statCards.map((card) => (
            <Link
              key={card.name}
              to={card.href}
              className="relative overflow-hidden rounded-lg bg-white px-6 py-5 shadow hover:shadow-md transition-shadow"
            >
              <div className="flex items-center">
                <div className={`flex h-12 w-12 items-center justify-center rounded-lg ${card.color}`}>
                  <card.icon className="h-6 w-6" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">{card.name}</p>
                  <div className="flex items-baseline">
                    <p className="text-2xl font-semibold text-gray-900">{card.value}</p>
                    {card.total !== undefined && (
                      <p className="ml-2 text-sm text-gray-500">of {card.total}</p>
                    )}
                  </div>
                  {card.subtext && (
                    <p className="text-xs text-gray-500 mt-1">{card.subtext}</p>
                  )}
                </div>
              </div>
            </Link>
          ))}
        </div>

        {/* Two Column Layout */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Recent Scans */}
          <div className="rounded-lg bg-white shadow">
            <div className="border-b border-gray-200 px-6 py-4">
              <h2 className="text-lg font-medium text-gray-900">Recent Scans</h2>
            </div>
            <div className="divide-y divide-gray-200">
              {stats.recent_scans.length === 0 ? (
                <div className="px-6 py-8 text-center text-sm text-gray-500">
                  No recent scans
                </div>
              ) : (
                stats.recent_scans.map((scan) => (
                  <div key={scan.id} className="px-6 py-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-900">{scan.name}</p>
                        <div className="flex items-center mt-1 text-xs text-gray-500">
                          <ClockIcon className="mr-1 h-3 w-3" />
                          {new Date(scan.created_at).toLocaleDateString()}
                        </div>
                      </div>
                      <span
                        className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                          scan.status === 'completed'
                            ? 'bg-green-100 text-green-800'
                            : scan.status === 'running'
                            ? 'bg-blue-100 text-blue-800'
                            : 'bg-gray-100 text-gray-800'
                        }`}
                      >
                        {scan.status}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Upcoming Milestones */}
          <div className="rounded-lg bg-white shadow">
            <div className="border-b border-gray-200 px-6 py-4">
              <h2 className="text-lg font-medium text-gray-900">Upcoming Milestones</h2>
            </div>
            <div className="divide-y divide-gray-200">
              {stats.upcoming_milestones.length === 0 ? (
                <div className="px-6 py-8 text-center text-sm text-gray-500">
                  No upcoming milestones
                </div>
              ) : (
                stats.upcoming_milestones.map((milestone) => (
                  <div key={milestone.id} className="px-6 py-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-900">{milestone.name}</p>
                        <p className="text-xs text-gray-500 mt-1">{milestone.engagement_name}</p>
                      </div>
                      <div className="text-right">
                        {milestone.due_date && (
                          <div className="flex items-center text-xs text-gray-500">
                            <CalendarIcon className="mr-1 h-3 w-3" />
                            {new Date(milestone.due_date).toLocaleDateString()}
                          </div>
                        )}
                        <span
                          className={`mt-1 inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                            milestone.status === 'completed'
                              ? 'bg-green-100 text-green-800'
                              : milestone.status === 'in_progress'
                              ? 'bg-blue-100 text-blue-800'
                              : milestone.status === 'overdue'
                              ? 'bg-red-100 text-red-800'
                              : 'bg-gray-100 text-gray-800'
                          }`}
                        >
                          {milestone.status}
                        </span>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
            {stats.upcoming_milestones.length > 0 && (
              <div className="border-t border-gray-200 px-6 py-3">
                <Link
                  to="/portal/engagements"
                  className="text-sm font-medium text-blue-600 hover:text-blue-500"
                >
                  View all engagements
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>
    </PortalLayout>
  );
}

export default PortalDashboard;
