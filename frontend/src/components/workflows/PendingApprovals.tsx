import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Clock,
  AlertTriangle,
  CheckCircle,
  Users,
  ArrowRight,
  Shield,
  Loader2,
  RefreshCw,
} from 'lucide-react';
import { formatDistanceToNow, isPast } from 'date-fns';
import { toast } from 'react-toastify';
import { workflowAPI } from '../../services/api';
import type { PendingApproval, WorkflowStats } from '../../types';
import Badge from '../ui/Badge';

interface PendingApprovalsProps {
  onViewWorkflow?: (instanceId: string, vulnerabilityId: string) => void;
}

export const PendingApprovals: React.FC<PendingApprovalsProps> = ({ onViewWorkflow }) => {
  const navigate = useNavigate();
  const [approvals, setApprovals] = useState<PendingApproval[]>([]);
  const [stats, setStats] = useState<WorkflowStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const loadData = async () => {
    try {
      const [approvalsRes, statsRes] = await Promise.all([
        workflowAPI.getPendingApprovals(),
        workflowAPI.getStats(),
      ]);
      setApprovals(approvalsRes.data);
      setStats(statsRes.data);
    } catch (error) {
      toast.error('Failed to load pending approvals');
      console.error(error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
  };

  const handleViewWorkflow = (approval: PendingApproval) => {
    if (onViewWorkflow) {
      onViewWorkflow(approval.instance_id, approval.vulnerability_id);
    } else {
      // Navigate to vulnerability detail with workflow tab
      navigate(`/vulnerabilities/${approval.vulnerability_id}?tab=workflow`);
    }
  };

  const getSeverityType = (severity: string): 'critical' | 'high' | 'medium' | 'low' => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'critical';
      case 'high':
        return 'high';
      case 'medium':
        return 'medium';
      default:
        return 'low';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Active Workflows</p>
                <p className="text-2xl font-semibold text-white">{stats.active_workflows}</p>
              </div>
              <Shield className="w-8 h-8 text-cyan-400 opacity-50" />
            </div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Pending Approvals</p>
                <p className="text-2xl font-semibold text-white">{stats.pending_approvals}</p>
              </div>
              <Users className="w-8 h-8 text-yellow-400 opacity-50" />
            </div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Completed Today</p>
                <p className="text-2xl font-semibold text-white">{stats.completed_today}</p>
              </div>
              <CheckCircle className="w-8 h-8 text-green-400 opacity-50" />
            </div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">SLA Breaches</p>
                <p className="text-2xl font-semibold text-white">{stats.sla_breaches}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-400 opacity-50" />
            </div>
          </div>
        </div>
      )}

      {/* Pending Approvals List */}
      <div className="bg-gray-900 rounded-lg border border-gray-700">
        <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
          <h3 className="text-lg font-medium text-white">Pending Approvals</h3>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-400 hover:text-white disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {approvals.length === 0 ? (
          <div className="px-4 py-12 text-center">
            <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-3 opacity-50" />
            <p className="text-gray-400">No pending approvals</p>
            <p className="text-sm text-gray-500 mt-1">
              You're all caught up! Workflows needing your approval will appear here.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-700">
            {approvals.map((approval) => {
              const isSlaBreach =
                approval.sla_breached ||
                (approval.sla_deadline && isPast(new Date(approval.sla_deadline)));

              return (
                <div
                  key={`${approval.instance_id}-${approval.stage_instance_id}`}
                  className="p-4 hover:bg-gray-800/50 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h4 className="font-medium text-white">{approval.vulnerability_title}</h4>
                        <Badge variant="severity" type={getSeverityType(approval.severity)}>
                          {approval.severity}
                        </Badge>
                        {isSlaBreach && (
                          <span className="px-2 py-0.5 rounded text-xs font-medium text-red-400 bg-red-900/30 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            SLA Breach
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-sm text-gray-400">
                        <span className="flex items-center gap-1">
                          <Shield className="w-4 h-4" />
                          {approval.stage_name}
                        </span>
                        <span className="text-gray-600">|</span>
                        <span className="capitalize">
                          {approval.stage_type.replace('_', ' ')}
                        </span>
                        <span className="text-gray-600">|</span>
                        <span className="flex items-center gap-1">
                          <Users className="w-4 h-4" />
                          {approval.approvals_received}/{approval.required_approvals} approvals
                        </span>
                      </div>
                      <div className="flex items-center gap-4 text-sm text-gray-500 mt-2">
                        <span className="flex items-center gap-1">
                          <Clock className="w-4 h-4" />
                          Entered{' '}
                          {formatDistanceToNow(new Date(approval.entered_at), { addSuffix: true })}
                        </span>
                        {approval.sla_deadline && (
                          <span
                            className={`flex items-center gap-1 ${
                              isSlaBreach ? 'text-red-400' : ''
                            }`}
                          >
                            <AlertTriangle className="w-4 h-4" />
                            SLA{' '}
                            {formatDistanceToNow(new Date(approval.sla_deadline), {
                              addSuffix: true,
                            })}
                          </span>
                        )}
                      </div>
                    </div>
                    <button
                      onClick={() => handleViewWorkflow(approval)}
                      className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded text-sm"
                    >
                      Review
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default PendingApprovals;
