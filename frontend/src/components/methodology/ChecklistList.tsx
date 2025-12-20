import React from 'react';
import type { ChecklistSummary } from '../../types';
import { ClipboardList, Plus, Trash2, Clock, CheckCircle, Archive } from 'lucide-react';
import ProgressBar from './ProgressBar';

interface ChecklistListProps {
  checklists: ChecklistSummary[];
  onSelect: (checklist: ChecklistSummary) => void;
  onDelete: (id: string) => void;
  onCreateNew: () => void;
}

const ChecklistList: React.FC<ChecklistListProps> = ({
  checklists,
  onSelect,
  onDelete,
  onCreateNew,
}) => {
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'archived':
        return <Archive className="h-4 w-4 text-slate-400" />;
      default:
        return <Clock className="h-4 w-4 text-yellow-400" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-500/20 text-green-400';
      case 'archived':
        return 'bg-slate-500/20 text-slate-400';
      default:
        return 'bg-yellow-500/20 text-yellow-400';
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  if (checklists.length === 0) {
    return (
      <div className="bg-dark-surface rounded-lg border border-dark-border p-8 text-center">
        <ClipboardList className="h-12 w-12 text-slate-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-white mb-2">No Checklists Yet</h3>
        <p className="text-slate-400 mb-6">
          Create your first methodology checklist to start tracking your testing progress.
        </p>
        <button
          onClick={onCreateNew}
          className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors"
        >
          <Plus className="h-4 w-4" />
          Create Checklist
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {checklists.map((checklist) => (
        <div
          key={checklist.id}
          className="bg-dark-surface rounded-lg border border-dark-border p-4 hover:border-primary/50 transition-colors cursor-pointer"
          onClick={() => onSelect(checklist)}
        >
          <div className="flex items-start justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg">
                <ClipboardList className="h-5 w-5 text-primary" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-white">
                  {checklist.name}
                </h3>
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <span>{checklist.template_name}</span>
                  <span>•</span>
                  <span>{checklist.total_items} items</span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span
                className={`flex items-center gap-1 px-2 py-1 text-xs rounded ${getStatusBadge(
                  checklist.status
                )}`}
              >
                {getStatusIcon(checklist.status)}
                {checklist.status.replace('_', ' ')}
              </span>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onDelete(checklist.id);
                }}
                className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          </div>

          {checklist.description && (
            <p className="text-sm text-slate-400 mb-3">{checklist.description}</p>
          )}

          <div className="mb-3">
            <ProgressBar progress={checklist.progress_percent} size="md" showLabel />
          </div>

          <div className="flex items-center gap-4 text-xs text-slate-500">
            <span>Created: {formatDate(checklist.created_at)}</span>
            <span>Updated: {formatDate(checklist.updated_at)}</span>
            {checklist.completed_at && (
              <span className="text-green-400">
                Completed: {formatDate(checklist.completed_at)}
              </span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};

export default ChecklistList;
