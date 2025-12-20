import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { ClipboardList, Loader, AlertTriangle, Calendar, PlayCircle, CheckCircle, ChevronRight } from 'lucide-react';
import WidgetContainer from './WidgetContainer';
import { vulnerabilityAPI } from '../../../services/api';
import type { VulnerabilityAssignmentWithUser, UserAssignmentStats } from '../../../types';
import { toast } from 'react-toastify';

interface MyAssignmentsWidgetProps {
  onRemove?: () => void;
}

const MyAssignmentsWidget: React.FC<MyAssignmentsWidgetProps> = ({ onRemove }) => {
  const navigate = useNavigate();
  const [stats, setStats] = useState<UserAssignmentStats | null>(null);
  const [assignments, setAssignments] = useState<VulnerabilityAssignmentWithUser[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const response = await vulnerabilityAPI.getMyAssignments({ status: '' });
      setStats(response.data.stats);
      // Show only top 5 assignments
      setAssignments(response.data.assignments.slice(0, 5));
    } catch (error) {
      console.error('Failed to fetch assignments:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleStatusChange = async (e: React.MouseEvent, vulnId: string, newStatus: string) => {
    e.stopPropagation();
    try {
      await vulnerabilityAPI.updateAssignment(vulnId, { status: newStatus });
      toast.success('Status updated');
      fetchData();
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
          Overdue
        </span>
      );
    }

    if (daysUntilDue !== null) {
      if (daysUntilDue === 0) {
        return <span className="text-yellow-400">Today</span>;
      }
      if (daysUntilDue <= 3) {
        return <span className="text-yellow-400">{daysUntilDue}d</span>;
      }
    }

    return <span className="text-gray-400">{formattedDate}</span>;
  };

  return (
    <WidgetContainer
      title="My Assignments"
      icon={<ClipboardList className="h-5 w-5" />}
      onRemove={onRemove}
    >
      {loading ? (
        <div className="flex items-center justify-center h-32">
          <Loader className="h-6 w-6 text-primary animate-spin" />
        </div>
      ) : (
        <>
          {/* Stats Summary */}
          {stats && (
            <div className="grid grid-cols-4 gap-2 mb-4 p-3 bg-dark-bg rounded-lg border border-dark-border">
              <div className="text-center">
                <div className="text-lg font-bold text-white">{stats.total}</div>
                <div className="text-xs text-slate-400">Total</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-red-400">{stats.overdue}</div>
                <div className="text-xs text-slate-400">Overdue</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-yellow-400">{stats.in_progress}</div>
                <div className="text-xs text-slate-400">In Progress</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-cyan-400">{stats.critical + stats.high}</div>
                <div className="text-xs text-slate-400">High+</div>
              </div>
            </div>
          )}

          {/* Assignments List */}
          {assignments.length === 0 ? (
            <div className="text-center text-slate-400 py-8">
              <CheckCircle className="h-12 w-12 mx-auto mb-2 text-green-500/50" />
              <p>No assignments</p>
              <p className="text-sm mt-1">You are all caught up!</p>
            </div>
          ) : (
            <div className="space-y-2">
              {assignments.map((vuln) => (
                <div
                  key={vuln.id}
                  className={`flex items-center justify-between p-3 bg-dark-bg rounded-lg border border-dark-border hover:border-primary cursor-pointer transition-colors ${
                    vuln.is_overdue ? 'border-red-900/50' : ''
                  }`}
                  onClick={() => navigate(`/remediation?vuln=${vuln.id}`)}
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <span className={getSeverityBadgeClass(vuln.severity)}>
                      {vuln.severity.charAt(0).toUpperCase()}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-white truncate text-sm">
                        {vuln.vulnerability_id}
                      </div>
                      <div className="text-xs text-slate-400">
                        {vuln.host_ip}{vuln.port ? `:${vuln.port}` : ''}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0" onClick={(e) => e.stopPropagation()}>
                    {/* Due Date */}
                    <div className="text-xs">
                      <Calendar className="h-3 w-3 inline mr-1 text-gray-500" />
                      {formatDueDate(vuln.due_date, vuln.days_until_due, vuln.is_overdue) || (
                        <span className="text-gray-500">--</span>
                      )}
                    </div>

                    {/* Quick Status Change */}
                    {vuln.status === 'open' && (
                      <button
                        onClick={(e) => handleStatusChange(e, vuln.id, 'in_progress')}
                        className="p-1 text-yellow-400 hover:bg-yellow-500/20 rounded transition-colors"
                        title="Start Working"
                      >
                        <PlayCircle className="h-4 w-4" />
                      </button>
                    )}
                    {vuln.status === 'in_progress' && (
                      <button
                        onClick={(e) => handleStatusChange(e, vuln.id, 'resolved')}
                        className="p-1 text-green-400 hover:bg-green-500/20 rounded transition-colors"
                        title="Mark Resolved"
                      >
                        <CheckCircle className="h-4 w-4" />
                      </button>
                    )}

                    <ChevronRight className="h-4 w-4 text-gray-500" />
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* View All Link */}
          {stats && stats.total > 5 && (
            <div className="pt-3 text-center">
              <button
                onClick={() => navigate('/remediation?assigned=me')}
                className="text-cyan-400 hover:text-cyan-300 text-sm font-medium"
              >
                View all {stats.total} assignments
              </button>
            </div>
          )}
        </>
      )}
    </WidgetContainer>
  );
};

export default MyAssignmentsWidget;
