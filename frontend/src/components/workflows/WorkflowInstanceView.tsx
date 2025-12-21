import React, { useState } from 'react';
import {
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Pause,
  Play,
  Ban,
  MessageSquare,
  Users,
  ArrowRight,
  Shield,
  FileCheck,
  Briefcase,
  Wrench,
  X,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { formatDistanceToNow, format, isPast } from 'date-fns';
import type {
  WorkflowInstanceDetail,
  StageInstanceWithDetails,
  WorkflowStage,
} from '../../types';

interface WorkflowInstanceViewProps {
  instance: WorkflowInstanceDetail;
  onApprove?: (comment?: string) => Promise<void>;
  onReject?: (comment: string, restartFromStage?: string) => Promise<void>;
  onAdvance?: (comment?: string) => Promise<void>;
  onHold?: (notes?: string) => Promise<void>;
  onResume?: () => Promise<void>;
  onCancel?: (comment?: string) => Promise<void>;
  canApprove?: boolean;
  isLoading?: boolean;
}

const STAGE_TYPE_ICONS: Record<string, React.FC<{ className?: string }>> = {
  assignment: Users,
  work: Wrench,
  review: FileCheck,
  verification: CheckCircle,
  cab_approval: Briefcase,
  deployment: Shield,
  closure: X,
};

const getStatusColor = (status: string) => {
  switch (status.toLowerCase()) {
    case 'completed':
      return 'text-green-400 bg-green-900/30';
    case 'active':
      return 'text-cyan-400 bg-cyan-900/30';
    case 'pending':
      return 'text-gray-400 bg-gray-700/50';
    case 'rejected':
      return 'text-red-400 bg-red-900/30';
    case 'skipped':
      return 'text-yellow-400 bg-yellow-900/30';
    case 'on_hold':
      return 'text-orange-400 bg-orange-900/30';
    case 'cancelled':
      return 'text-gray-500 bg-gray-800';
    default:
      return 'text-gray-400 bg-gray-700/50';
  }
};

const getStatusIcon = (status: string) => {
  switch (status.toLowerCase()) {
    case 'completed':
      return CheckCircle;
    case 'active':
      return Play;
    case 'rejected':
      return XCircle;
    case 'on_hold':
      return Pause;
    case 'cancelled':
      return Ban;
    default:
      return Clock;
  }
};

export const WorkflowInstanceView: React.FC<WorkflowInstanceViewProps> = ({
  instance,
  onApprove,
  onReject,
  onAdvance,
  onHold,
  onResume,
  onCancel,
  canApprove = true,
  isLoading = false,
}) => {
  const [comment, setComment] = useState('');
  const [showActions, setShowActions] = useState(true);
  const [expandedStage, setExpandedStage] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const isActive = instance.status === 'active';
  const isOnHold = instance.status === 'on_hold';
  const currentStageInstance = instance.stage_instances.find(
    (si) => si.stage_id === instance.current_stage_id
  );

  const handleAction = async (action: string, fn?: () => Promise<void>) => {
    if (!fn) return;
    setActionLoading(action);
    try {
      await fn();
    } finally {
      setActionLoading(null);
    }
  };

  const handleApprove = () => {
    if (onApprove) {
      handleAction('approve', () => onApprove(comment || undefined));
    }
    setComment('');
  };

  const handleReject = () => {
    if (!comment.trim()) {
      alert('Please provide a reason for rejection');
      return;
    }
    if (onReject) {
      handleAction('reject', () => onReject(comment));
    }
    setComment('');
  };

  const handleAdvance = () => {
    if (onAdvance) {
      handleAction('advance', () => onAdvance(comment || undefined));
    }
    setComment('');
  };

  const renderStageTimeline = () => {
    const sortedStages = [...instance.stage_instances].sort(
      (a, b) => a.stage.stage_order - b.stage.stage_order
    );

    return (
      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gray-700" />

        <div className="space-y-4">
          {sortedStages.map((stageInstance, index) => {
            const isExpanded = expandedStage === stageInstance.id;
            const isCurrent = stageInstance.stage_id === instance.current_stage_id;
            const StatusIcon = getStatusIcon(stageInstance.status);
            const StageIcon = STAGE_TYPE_ICONS[stageInstance.stage.stage_type] || Wrench;
            const statusColor = getStatusColor(stageInstance.status);

            return (
              <div key={stageInstance.id} className="relative pl-14">
                {/* Timeline dot */}
                <div
                  className={`absolute left-4 w-5 h-5 rounded-full flex items-center justify-center ${
                    isCurrent
                      ? 'bg-cyan-500 ring-4 ring-cyan-500/30'
                      : stageInstance.status === 'completed'
                      ? 'bg-green-500'
                      : 'bg-gray-600'
                  }`}
                >
                  <StatusIcon className="w-3 h-3 text-white" />
                </div>

                {/* Stage Card */}
                <div
                  className={`bg-gray-800 rounded-lg border ${
                    isCurrent ? 'border-cyan-500' : 'border-gray-700'
                  }`}
                >
                  <button
                    onClick={() => setExpandedStage(isExpanded ? null : stageInstance.id)}
                    className="w-full p-4 flex items-center justify-between text-left"
                  >
                    <div className="flex items-center gap-3">
                      <StageIcon className="w-5 h-5 text-gray-400" />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-white">
                            {stageInstance.stage.name}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor}`}
                          >
                            {stageInstance.status.replace('_', ' ')}
                          </span>
                          {stageInstance.sla_breached && (
                            <span className="px-2 py-0.5 rounded text-xs font-medium text-red-400 bg-red-900/30">
                              SLA Breached
                            </span>
                          )}
                        </div>
                        <div className="text-sm text-gray-400">
                          {stageInstance.stage.description ||
                            `Stage ${index + 1} of ${sortedStages.length}`}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {stageInstance.sla_deadline && (
                        <div
                          className={`text-sm ${
                            isPast(new Date(stageInstance.sla_deadline))
                              ? 'text-red-400'
                              : 'text-gray-400'
                          }`}
                        >
                          <Clock className="w-4 h-4 inline mr-1" />
                          {formatDistanceToNow(new Date(stageInstance.sla_deadline), {
                            addSuffix: true,
                          })}
                        </div>
                      )}
                      {stageInstance.stage.required_approvals > 0 && (
                        <div className="text-sm text-gray-400">
                          <Users className="w-4 h-4 inline mr-1" />
                          {stageInstance.approvals_received}/{stageInstance.stage.required_approvals}
                        </div>
                      )}
                      {isExpanded ? (
                        <ChevronUp className="w-5 h-5 text-gray-400" />
                      ) : (
                        <ChevronDown className="w-5 h-5 text-gray-400" />
                      )}
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="px-4 pb-4 border-t border-gray-700 mt-2 pt-4">
                      <div className="grid grid-cols-2 gap-4 text-sm mb-4">
                        <div>
                          <span className="text-gray-400">Entered:</span>
                          <span className="ml-2 text-white">
                            {format(new Date(stageInstance.entered_at), 'PPp')}
                          </span>
                        </div>
                        {stageInstance.completed_at && (
                          <div>
                            <span className="text-gray-400">Completed:</span>
                            <span className="ml-2 text-white">
                              {format(new Date(stageInstance.completed_at), 'PPp')}
                            </span>
                          </div>
                        )}
                        <div>
                          <span className="text-gray-400">Stage Type:</span>
                          <span className="ml-2 text-white capitalize">
                            {stageInstance.stage.stage_type.replace('_', ' ')}
                          </span>
                        </div>
                        {stageInstance.stage.approver_role && (
                          <div>
                            <span className="text-gray-400">Approver Role:</span>
                            <span className="ml-2 text-white">
                              {stageInstance.stage.approver_role}
                            </span>
                          </div>
                        )}
                      </div>

                      {/* Approvals */}
                      {stageInstance.approvals.length > 0 && (
                        <div className="mt-4">
                          <h4 className="text-sm font-medium text-gray-300 mb-2">Approvals</h4>
                          <div className="space-y-2">
                            {stageInstance.approvals.map((approval) => (
                              <div
                                key={approval.id}
                                className="flex items-start gap-2 p-2 bg-gray-700/50 rounded"
                              >
                                {approval.approved ? (
                                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
                                ) : (
                                  <XCircle className="w-4 h-4 text-red-400 mt-0.5" />
                                )}
                                <div className="flex-1">
                                  <div className="flex items-center justify-between">
                                    <span className="text-sm text-white">{approval.username}</span>
                                    <span className="text-xs text-gray-400">
                                      {formatDistanceToNow(new Date(approval.created_at), {
                                        addSuffix: true,
                                      })}
                                    </span>
                                  </div>
                                  {approval.comment && (
                                    <p className="text-sm text-gray-400 mt-1">{approval.comment}</p>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {stageInstance.notes && (
                        <div className="mt-4">
                          <h4 className="text-sm font-medium text-gray-300 mb-1">Notes</h4>
                          <p className="text-sm text-gray-400">{stageInstance.notes}</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            {instance.template.name}
            <span className={`px-2 py-0.5 rounded text-sm ${getStatusColor(instance.status)}`}>
              {instance.status.replace('_', ' ')}
            </span>
          </h3>
          <p className="text-sm text-gray-400 mt-1">
            Started {formatDistanceToNow(new Date(instance.started_at), { addSuffix: true })}
            {instance.completed_at && (
              <>
                {' '}
                - Completed{' '}
                {formatDistanceToNow(new Date(instance.completed_at), { addSuffix: true })}
              </>
            )}
          </p>
        </div>
        {instance.notes && (
          <div className="bg-gray-800 rounded px-3 py-2 max-w-xs">
            <MessageSquare className="w-4 h-4 text-gray-400 inline mr-2" />
            <span className="text-sm text-gray-300">{instance.notes}</span>
          </div>
        )}
      </div>

      {/* Current Stage Alert */}
      {isActive && currentStageInstance && (
        <div className="bg-cyan-900/20 border border-cyan-500/30 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <ArrowRight className="w-5 h-5 text-cyan-400" />
            <span className="text-cyan-300 font-medium">Current Stage:</span>
            <span className="text-white">{instance.current_stage.name}</span>
          </div>
          {currentStageInstance.sla_deadline && (
            <div
              className={`text-sm ${
                isPast(new Date(currentStageInstance.sla_deadline))
                  ? 'text-red-400'
                  : 'text-gray-400'
              }`}
            >
              <Clock className="w-4 h-4 inline mr-1" />
              SLA:{' '}
              {formatDistanceToNow(new Date(currentStageInstance.sla_deadline), {
                addSuffix: true,
              })}
              {currentStageInstance.sla_breached && (
                <span className="ml-2 text-red-400">
                  <AlertTriangle className="w-4 h-4 inline" /> Breached
                </span>
              )}
            </div>
          )}
        </div>
      )}

      {/* Stage Timeline */}
      <div className="bg-gray-900 rounded-lg p-4">
        <h4 className="text-sm font-medium text-gray-300 mb-4">Workflow Progress</h4>
        {renderStageTimeline()}
      </div>

      {/* Actions */}
      {(isActive || isOnHold) && canApprove && (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
          <button
            onClick={() => setShowActions(!showActions)}
            className="flex items-center justify-between w-full text-left"
          >
            <span className="font-medium text-white">Actions</span>
            {showActions ? (
              <ChevronUp className="w-5 h-5 text-gray-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-gray-400" />
            )}
          </button>

          {showActions && (
            <div className="mt-4 space-y-4">
              {/* Comment Input */}
              <div>
                <label className="block text-sm text-gray-400 mb-1">
                  Comment (optional for approve, required for reject)
                </label>
                <textarea
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                  rows={2}
                  placeholder="Add a comment..."
                />
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap gap-3">
                {isActive && (
                  <>
                    {currentStageInstance && currentStageInstance.stage.required_approvals > 0 && onApprove && (
                      <button
                        onClick={handleApprove}
                        disabled={isLoading || actionLoading !== null}
                        className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded disabled:opacity-50"
                      >
                        <CheckCircle className="w-4 h-4" />
                        {actionLoading === 'approve' ? 'Approving...' : 'Approve'}
                      </button>
                    )}
                    {currentStageInstance && currentStageInstance.stage.required_approvals === 0 && onAdvance && (
                      <button
                        onClick={handleAdvance}
                        disabled={isLoading || actionLoading !== null}
                        className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded disabled:opacity-50"
                      >
                        <ArrowRight className="w-4 h-4" />
                        {actionLoading === 'advance' ? 'Advancing...' : 'Advance'}
                      </button>
                    )}
                    {onReject && (
                      <button
                        onClick={handleReject}
                        disabled={isLoading || actionLoading !== null}
                        className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded disabled:opacity-50"
                      >
                        <XCircle className="w-4 h-4" />
                        {actionLoading === 'reject' ? 'Rejecting...' : 'Reject'}
                      </button>
                    )}
                    {onHold && (
                      <button
                        onClick={() => handleAction('hold', () => onHold(comment || undefined))}
                        disabled={isLoading || actionLoading !== null}
                        className="flex items-center gap-2 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded disabled:opacity-50"
                      >
                        <Pause className="w-4 h-4" />
                        {actionLoading === 'hold' ? 'Holding...' : 'Put on Hold'}
                      </button>
                    )}
                    {onCancel && (
                      <button
                        onClick={() => handleAction('cancel', () => onCancel(comment || undefined))}
                        disabled={isLoading || actionLoading !== null}
                        className="flex items-center gap-2 px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded disabled:opacity-50"
                      >
                        <Ban className="w-4 h-4" />
                        {actionLoading === 'cancel' ? 'Cancelling...' : 'Cancel Workflow'}
                      </button>
                    )}
                  </>
                )}
                {isOnHold && onResume && (
                  <button
                    onClick={() => handleAction('resume', onResume)}
                    disabled={isLoading || actionLoading !== null}
                    className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded disabled:opacity-50"
                  >
                    <Play className="w-4 h-4" />
                    {actionLoading === 'resume' ? 'Resuming...' : 'Resume Workflow'}
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default WorkflowInstanceView;
