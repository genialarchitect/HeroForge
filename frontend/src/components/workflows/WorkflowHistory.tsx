import React from 'react';
import {
  CheckCircle,
  XCircle,
  ArrowRight,
  Play,
  Pause,
  Ban,
  RotateCcw,
  User,
  MessageSquare,
} from 'lucide-react';
import { format, formatDistanceToNow } from 'date-fns';
import type { WorkflowTransitionWithUser } from '../../types';

interface WorkflowHistoryProps {
  transitions: WorkflowTransitionWithUser[];
  stageNames?: Record<string, string>;
}

const getActionIcon = (action: string) => {
  switch (action.toLowerCase()) {
    case 'started':
      return Play;
    case 'advanced':
      return ArrowRight;
    case 'approved':
      return CheckCircle;
    case 'rejected':
      return XCircle;
    case 'completed':
      return CheckCircle;
    case 'cancelled':
      return Ban;
    case 'on_hold':
      return Pause;
    case 'resumed':
      return Play;
    case 'sent_back':
      return RotateCcw;
    default:
      return ArrowRight;
  }
};

const getActionColor = (action: string) => {
  switch (action.toLowerCase()) {
    case 'approved':
    case 'completed':
      return 'text-green-400 bg-green-900/30';
    case 'rejected':
    case 'cancelled':
      return 'text-red-400 bg-red-900/30';
    case 'on_hold':
    case 'sent_back':
      return 'text-orange-400 bg-orange-900/30';
    case 'started':
    case 'resumed':
    case 'advanced':
      return 'text-cyan-400 bg-cyan-900/30';
    default:
      return 'text-gray-400 bg-gray-700';
  }
};

const formatAction = (action: string): string => {
  return action.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());
};

export const WorkflowHistory: React.FC<WorkflowHistoryProps> = ({
  transitions,
  stageNames = {},
}) => {
  if (transitions.length === 0) {
    return (
      <div className="text-center py-8">
        <MessageSquare className="w-12 h-12 text-gray-600 mx-auto mb-3" />
        <p className="text-gray-400">No workflow history yet</p>
      </div>
    );
  }

  // Sort by date descending (newest first)
  const sortedTransitions = [...transitions].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  );

  return (
    <div className="relative">
      {/* Timeline line */}
      <div className="absolute left-4 top-2 bottom-2 w-0.5 bg-gray-700" />

      <div className="space-y-4">
        {sortedTransitions.map((transition, index) => {
          const ActionIcon = getActionIcon(transition.action);
          const actionColor = getActionColor(transition.action);
          const fromStageName = transition.from_stage_id
            ? stageNames[transition.from_stage_id]
            : null;
          const toStageName = stageNames[transition.to_stage_id];

          return (
            <div key={transition.id} className="relative pl-10">
              {/* Timeline dot */}
              <div
                className={`absolute left-2 w-5 h-5 rounded-full flex items-center justify-center ${actionColor}`}
              >
                <ActionIcon className="w-3 h-3" />
              </div>

              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <span className={`px-2 py-0.5 rounded text-sm font-medium ${actionColor}`}>
                      {formatAction(transition.action)}
                    </span>
                    {fromStageName && toStageName && fromStageName !== toStageName && (
                      <span className="ml-2 text-sm text-gray-400">
                        {fromStageName} <ArrowRight className="w-4 h-4 inline mx-1" /> {toStageName}
                      </span>
                    )}
                    {!fromStageName && toStageName && (
                      <span className="ml-2 text-sm text-gray-400">{toStageName}</span>
                    )}
                  </div>
                  <div className="text-right">
                    <div
                      className="text-sm text-gray-400"
                      title={format(new Date(transition.created_at), 'PPpp')}
                    >
                      {formatDistanceToNow(new Date(transition.created_at), { addSuffix: true })}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 text-sm text-gray-300">
                  <User className="w-4 h-4 text-gray-500" />
                  <span>{transition.username}</span>
                </div>

                {transition.comment && (
                  <div className="mt-3 p-3 bg-gray-700/50 rounded">
                    <MessageSquare className="w-4 h-4 text-gray-500 inline mr-2" />
                    <span className="text-sm text-gray-300">{transition.comment}</span>
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

export default WorkflowHistory;
