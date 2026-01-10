import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { PortalLayout } from '../../components/portal/PortalLayout';
import { portalDashboardAPI } from '../../services/portalApi';
import type { PortalDashboardStats } from '../../types';
import {
  Folder,
  ShieldAlert,
  FileText,
  AlertTriangle,
  Clock,
  Calendar,
} from 'lucide-react';

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
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"></div>
        </div>
      </PortalLayout>
    );
  }

  if (error || !stats) {
    return (
      <PortalLayout>
        <div className="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4 text-red-700 dark:text-red-300">
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
      icon: Folder,
      color: 'text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-900/30',
      href: '/portal/engagements',
    },
    {
      name: 'Open Vulnerabilities',
      value: stats.open_vulnerabilities,
      subtext: `${stats.critical_vulnerabilities} critical, ${stats.high_vulnerabilities} high`,
      icon: ShieldAlert,
      color: stats.critical_vulnerabilities > 0
        ? 'text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-900/30'
        : 'text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-900/30',
      href: '/portal/vulnerabilities',
    },
    {
      name: 'Available Reports',
      value: stats.available_reports,
      icon: FileText,
      color: 'text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/30',
      href: '/portal/reports',
    },
  ];

  return (
    <PortalLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
            Welcome back, {stats.customer_name}
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Here's an overview of your security posture
          </p>
        </div>

        {/* Critical Alert Banner */}
        {stats.critical_vulnerabilities > 0 && (
          <div className="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4">
            <div className="flex items-center">
              <AlertTriangle className="h-6 w-6 text-red-600 dark:text-red-400 mr-3 flex-shrink-0" />
              <div className="flex-1">
                <h3 className="text-sm font-medium text-red-800 dark:text-red-200">
                  Critical Vulnerabilities Detected
                </h3>
                <p className="text-sm text-red-700 dark:text-red-300 mt-1">
                  You have {stats.critical_vulnerabilities} critical vulnerabilit{stats.critical_vulnerabilities === 1 ? 'y' : 'ies'} that require immediate attention.
                </p>
              </div>
              <Link
                to="/portal/vulnerabilities?severity=critical"
                className="ml-4 rounded-lg bg-red-600 hover:bg-red-700 px-4 py-2 text-sm font-medium text-white transition-colors"
              >
                View Details
              </Link>
            </div>
          </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {statCards.map((card) => {
            const Icon = card.icon;
            return (
              <Link
                key={card.name}
                to={card.href}
                className="relative overflow-hidden rounded-lg bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border px-6 py-5 hover:border-primary/50 transition-colors"
              >
                <div className="flex items-center">
                  <div className={`flex h-12 w-12 items-center justify-center rounded-lg ${card.color}`}>
                    <Icon className="h-6 w-6" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-slate-500 dark:text-slate-400">{card.name}</p>
                    <div className="flex items-baseline">
                      <p className="text-2xl font-semibold text-slate-900 dark:text-white">{card.value}</p>
                      {card.total !== undefined && (
                        <p className="ml-2 text-sm text-slate-500 dark:text-slate-400">of {card.total}</p>
                      )}
                    </div>
                    {card.subtext && (
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{card.subtext}</p>
                    )}
                  </div>
                </div>
              </Link>
            );
          })}
        </div>

        {/* Two Column Layout */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Recent Scans */}
          <div className="rounded-lg bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border overflow-hidden">
            <div className="border-b border-light-border dark:border-dark-border px-6 py-4">
              <h2 className="text-lg font-medium text-slate-900 dark:text-white">Recent Scans</h2>
            </div>
            <div className="divide-y divide-light-border dark:divide-dark-border">
              {stats.recent_scans.length === 0 ? (
                <div className="px-6 py-8 text-center text-sm text-slate-500 dark:text-slate-400">
                  No recent scans
                </div>
              ) : (
                stats.recent_scans.map((scan) => (
                  <div key={scan.id} className="px-6 py-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-slate-900 dark:text-white">{scan.name}</p>
                        <div className="flex items-center mt-1 text-xs text-slate-500 dark:text-slate-400">
                          <Clock className="mr-1 h-3 w-3" />
                          {new Date(scan.created_at).toLocaleDateString()}
                        </div>
                      </div>
                      <span
                        className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                          scan.status === 'completed'
                            ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
                            : scan.status === 'running'
                            ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300'
                            : 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300'
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
          <div className="rounded-lg bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border overflow-hidden">
            <div className="border-b border-light-border dark:border-dark-border px-6 py-4">
              <h2 className="text-lg font-medium text-slate-900 dark:text-white">Upcoming Milestones</h2>
            </div>
            <div className="divide-y divide-light-border dark:divide-dark-border">
              {stats.upcoming_milestones.length === 0 ? (
                <div className="px-6 py-8 text-center text-sm text-slate-500 dark:text-slate-400">
                  No upcoming milestones
                </div>
              ) : (
                stats.upcoming_milestones.map((milestone) => (
                  <div key={milestone.id} className="px-6 py-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-slate-900 dark:text-white">{milestone.name}</p>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{milestone.engagement_name}</p>
                      </div>
                      <div className="text-right">
                        {milestone.due_date && (
                          <div className="flex items-center text-xs text-slate-500 dark:text-slate-400">
                            <Calendar className="mr-1 h-3 w-3" />
                            {new Date(milestone.due_date).toLocaleDateString()}
                          </div>
                        )}
                        <span
                          className={`mt-1 inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                            milestone.status === 'completed'
                              ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
                              : milestone.status === 'in_progress'
                              ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300'
                              : milestone.status === 'overdue'
                              ? 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300'
                              : 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300'
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
              <div className="border-t border-light-border dark:border-dark-border px-6 py-3">
                <Link
                  to="/portal/engagements"
                  className="text-sm font-medium text-primary hover:text-primary-dark"
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
