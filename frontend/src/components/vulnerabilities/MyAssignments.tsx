import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';
import { vulnerabilityAPI } from '../../services/api';
import type { VulnerabilityAssignmentWithUser, UserAssignmentStats } from '../../types';
import {
  AlertTriangle,
  Clock,
  CheckCircle,
  PlayCircle,
  Calendar,
  Shield,
  ChevronRight,
  RefreshCw,
} from 'lucide-react';

interface MyAssignmentsProps {
  compact?: boolean;
  maxItems?: number;
}

const MyAssignments: React.FC<MyAssignmentsProps> = ({ compact = false, maxItems }) => {
  const navigate = useNavigate();
  const [stats, setStats] = useState<UserAssignmentStats | null>(null);
  const [assignments, setAssignments] = useState<VulnerabilityAssignmentWithUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [overdueOnly, setOverdueOnly] = useState(false);

  const loadAssignments = useCallback(async () => {
    try {
      setLoading(true);
      const response = await vulnerabilityAPI.getMyAssignments({
        status: statusFilter || undefined,
        overdue: overdueOnly || undefined,
      });
      setStats(response.data.stats);
      setAssignments(response.data.assignments);
    } catch (error) {
      console.error('Failed to load assignments:', error);
      toast.error('Failed to load your assignments');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, overdueOnly]);

  useEffect(() => {
    loadAssignments();
  }, [loadAssignments]);

  const handleStatusChange = async (vulnId: string, newStatus: string) => {
    try {
      await vulnerabilityAPI.updateAssignment(vulnId, { status: newStatus });
      toast.success('Status updated');
      loadAssignments();
    } catch (error) {
      console.error('Failed to update status:', error);
      toast.error('Failed to update status');
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    const baseClass = 'px-2 py-0.5 text-xs font-semibold rounded-full';
    switch (severity.toLowerCase()) {
      case 'critical':
        return `${baseClass} bg-red-500/20 text-red-400`;
      case 'high':
        return `${baseClass} bg-orange-500/20 text-orange-400`;
      case 'medium':
        return `${baseClass} bg-yellow-500/20 text-yellow-400`;
      case 'low':
        return `${baseClass} bg-blue-500/20 text-blue-400`;
      default:
        return `${baseClass} bg-gray-500/20 text-gray-400`;
    }
  };

  const formatDueDate = (dueDate: string | null, daysUntilDue: number | null, isOverdue: boolean) => {
    if (!dueDate) return null;
    const date = new Date(dueDate);
    const formattedDate = date.toLocaleDateString();

    if (isOverdue) {
      return (
        <span className="text-red-400 flex items-center gap-1">
          <AlertTriangle className="h-3 w-3" />
          {formattedDate} (Overdue)
        </span>
      );
    }

    if (daysUntilDue !== null) {
      if (daysUntilDue === 0) {
        return <span className="text-yellow-400">{formattedDate} (Today)</span>;
      }
      if (daysUntilDue <= 3) {
        return <span className="text-yellow-400">{formattedDate} ({daysUntilDue}d)</span>;
      }
    }

    return <span className="text-gray-400">{formattedDate}</span>;
  };

  // Group assignments by due date category
  const groupedAssignments = {
    overdue: assignments.filter((a) => a.is_overdue),
    today: assignments.filter(
      (a) => !a.is_overdue && a.days_until_due !== null && a.days_until_due === 0
    ),
    thisWeek: assignments.filter(
      (a) => !a.is_overdue && a.days_until_due !== null && a.days_until_due > 0 && a.days_until_due <= 7
    ),
    later: assignments.filter(
      (a) => !a.is_overdue && (a.days_until_due === null || a.days_until_due > 7)
    ),
  };

  const displayAssignments = maxItems ? assignments.slice(0, maxItems) : assignments;

  if (loading) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <div className="flex justify-center items-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700">
      {/* Header */}
      <div className="p-4 border-b border-gray-700 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-cyan-400" />
          <h3 className="text-lg font-semibold text-white">My Assignments</h3>
        </div>
        <button
          onClick={loadAssignments}
          className="p-2 text-gray-400 hover:text-white transition-colors rounded hover:bg-gray-700"
          title="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Stats Summary */}
      {stats && (
        <div className={`grid ${compact ? 'grid-cols-4' : 'grid-cols-4 md:grid-cols-8'} gap-2 p-4 bg-gray-900/50`}>
          <div className="text-center">
            <div className="text-xs text-gray-400">Total</div>
            <div className="text-xl font-bold text-white">{stats.total}</div>
          </div>
          <div className="text-center">
            <div className="text-xs text-gray-400">Open</div>
            <div className="text-xl font-bold text-red-400">{stats.open}</div>
          </div>
          <div className="text-center">
            <div className="text-xs text-gray-400">In Progress</div>
            <div className="text-xl font-bold text-yellow-400">{stats.in_progress}</div>
          </div>
          <div className="text-center">
            <div className="text-xs text-gray-400">Overdue</div>
            <div className="text-xl font-bold text-red-500">{stats.overdue}</div>
          </div>
          {!compact && (
            <>
              <div className="text-center">
                <div className="text-xs text-gray-400">Due Today</div>
                <div className="text-xl font-bold text-yellow-500">{stats.due_today}</div>
              </div>
              <div className="text-center">
                <div className="text-xs text-gray-400">This Week</div>
                <div className="text-xl font-bold text-blue-400">{stats.due_this_week}</div>
              </div>
              <div className="text-center">
                <div className="text-xs text-gray-400">Critical</div>
                <div className="text-xl font-bold text-red-500">{stats.critical}</div>
              </div>
              <div className="text-center">
                <div className="text-xs text-gray-400">High</div>
                <div className="text-xl font-bold text-orange-400">{stats.high}</div>
              </div>
            </>
          )}
        </div>
      )}

      {/* Filters (only show in non-compact mode) */}
      {!compact && (
        <div className="p-4 border-b border-gray-700 flex flex-wrap gap-4 items-center">
          <div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="block rounded-md border-gray-600 bg-gray-700 text-white text-sm shadow-sm focus:border-cyan-500 focus:ring-cyan-500"
            >
              <option value="">All Open</option>
              <option value="open">Open Only</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={overdueOnly}
              onChange={(e) => setOverdueOnly(e.target.checked)}
              className="rounded border-gray-600 bg-gray-700 text-cyan-500 focus:ring-cyan-500"
            />
            <span className="text-sm text-gray-300 flex items-center gap-1">
              <AlertTriangle className="h-4 w-4 text-red-400" />
              Overdue Only
            </span>
          </label>
        </div>
      )}

      {/* Assignments List */}
      <div className="divide-y divide-gray-700">
        {displayAssignments.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            <CheckCircle className="h-12 w-12 mx-auto mb-2 text-green-500/50" />
            <p>No assignments found</p>
            {overdueOnly && <p className="text-sm mt-1">No overdue items - great job!</p>}
          </div>
        ) : (
          displayAssignments.map((vuln) => (
            <div
              key={vuln.id}
              className={`p-4 hover:bg-gray-750 transition-colors cursor-pointer ${
                vuln.is_overdue ? 'bg-red-900/10' : ''
              }`}
              onClick={() => navigate(`/remediation?vuln=${vuln.id}`)}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={getSeverityBadgeClass(vuln.severity)}>
                      {vuln.severity.toUpperCase()}
                    </span>
                    <span className="text-sm font-medium text-white truncate">
                      {vuln.vulnerability_id}
                    </span>
                  </div>
                  <div className="text-xs text-gray-400 flex flex-wrap items-center gap-2">
                    <span>{vuln.host_ip}{vuln.port ? `:${vuln.port}` : ''}</span>
                    {vuln.scan_name && (
                      <>
                        <span className="text-gray-600">|</span>
                        <span className="truncate max-w-[150px]">{vuln.scan_name}</span>
                      </>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3 flex-shrink-0">
                  {/* Due Date */}
                  <div className="text-xs">
                    <Calendar className="h-3 w-3 inline mr-1 text-gray-500" />
                    {formatDueDate(vuln.due_date, vuln.days_until_due, vuln.is_overdue) || (
                      <span className="text-gray-500">No due date</span>
                    )}
                  </div>

                  {/* Quick Status Change */}
                  <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                    {vuln.status === 'open' && (
                      <button
                        onClick={() => handleStatusChange(vuln.id, 'in_progress')}
                        className="p-1.5 text-yellow-400 hover:bg-yellow-500/20 rounded transition-colors"
                        title="Start Working"
                      >
                        <PlayCircle className="h-4 w-4" />
                      </button>
                    )}
                    {vuln.status === 'in_progress' && (
                      <button
                        onClick={() => handleStatusChange(vuln.id, 'resolved')}
                        className="p-1.5 text-green-400 hover:bg-green-500/20 rounded transition-colors"
                        title="Mark Resolved"
                      >
                        <CheckCircle className="h-4 w-4" />
                      </button>
                    )}
                    <span
                      className={`px-2 py-0.5 text-xs rounded ${
                        vuln.status === 'open'
                          ? 'bg-red-500/20 text-red-400'
                          : vuln.status === 'in_progress'
                            ? 'bg-yellow-500/20 text-yellow-400'
                            : 'bg-gray-500/20 text-gray-400'
                      }`}
                    >
                      {vuln.status.replace('_', ' ')}
                    </span>
                  </div>

                  <ChevronRight className="h-4 w-4 text-gray-500" />
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* View All Link (for compact mode with more items) */}
      {compact && maxItems && assignments.length > maxItems && (
        <div className="p-3 border-t border-gray-700 text-center">
          <button
            onClick={() => navigate('/remediation?assigned=me')}
            className="text-cyan-400 hover:text-cyan-300 text-sm font-medium"
          >
            View all {assignments.length} assignments
          </button>
        </div>
      )}

      {/* Grouped View (for non-compact mode) */}
      {!compact && !overdueOnly && assignments.length > 0 && (
        <div className="p-4 border-t border-gray-700 bg-gray-900/30">
          <div className="text-xs text-gray-400 mb-2">Summary by Due Date</div>
          <div className="flex flex-wrap gap-4">
            {groupedAssignments.overdue.length > 0 && (
              <div className="flex items-center gap-1 text-red-400">
                <AlertTriangle className="h-3 w-3" />
                <span className="text-sm font-medium">{groupedAssignments.overdue.length} overdue</span>
              </div>
            )}
            {groupedAssignments.today.length > 0 && (
              <div className="flex items-center gap-1 text-yellow-400">
                <Clock className="h-3 w-3" />
                <span className="text-sm font-medium">{groupedAssignments.today.length} due today</span>
              </div>
            )}
            {groupedAssignments.thisWeek.length > 0 && (
              <div className="flex items-center gap-1 text-blue-400">
                <Calendar className="h-3 w-3" />
                <span className="text-sm font-medium">{groupedAssignments.thisWeek.length} this week</span>
              </div>
            )}
            {groupedAssignments.later.length > 0 && (
              <div className="flex items-center gap-1 text-gray-400">
                <Calendar className="h-3 w-3" />
                <span className="text-sm font-medium">{groupedAssignments.later.length} later</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default MyAssignments;
