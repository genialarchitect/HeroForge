import React, { useState } from 'react';
import type { ChecklistItemWithTemplate, ChecklistItemStatus } from '../../types';
import {
  CheckCircle2,
  XCircle,
  Circle,
  Clock,
  Ban,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileText,
  Wrench,
  BookOpen,
} from 'lucide-react';

interface ItemCardProps {
  item: ChecklistItemWithTemplate;
  isUpdating: boolean;
  onStatusChange: (status: ChecklistItemStatus) => void;
  onNotesChange: (notes: string) => void;
}

const ItemCard: React.FC<ItemCardProps> = ({
  item,
  isUpdating,
  onStatusChange,
  onNotesChange,
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [notes, setNotes] = useState(item.notes || '');
  const [showNotes, setShowNotes] = useState(false);

  const statusConfig: Record<
    ChecklistItemStatus,
    { icon: typeof Circle; color: string; bg: string; label: string }
  > = {
    not_started: {
      icon: Circle,
      color: 'text-slate-500',
      bg: 'bg-slate-500/20',
      label: 'Not Started',
    },
    in_progress: {
      icon: Clock,
      color: 'text-yellow-400',
      bg: 'bg-yellow-500/20',
      label: 'In Progress',
    },
    pass: {
      icon: CheckCircle2,
      color: 'text-green-400',
      bg: 'bg-green-500/20',
      label: 'Pass',
    },
    fail: {
      icon: XCircle,
      color: 'text-red-400',
      bg: 'bg-red-500/20',
      label: 'Fail',
    },
    na: {
      icon: Ban,
      color: 'text-slate-400',
      bg: 'bg-slate-500/20',
      label: 'N/A',
    },
  };

  const currentStatus = statusConfig[item.status];
  const StatusIcon = currentStatus.icon;

  const parseJsonArray = (json: string | null): string[] => {
    if (!json) return [];
    try {
      return JSON.parse(json);
    } catch {
      return [];
    }
  };

  const tools = parseJsonArray(item.tools);
  const references = parseJsonArray(item.references);

  const handleNotesBlur = () => {
    if (notes !== (item.notes || '')) {
      onNotesChange(notes);
    }
  };

  return (
    <div className={`p-4 ${isUpdating ? 'opacity-50' : ''}`}>
      <div className="flex items-start justify-between gap-4">
        {/* Item Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            {item.template_item_code && (
              <span className="px-2 py-0.5 text-xs font-mono bg-primary/10 text-primary rounded">
                {item.template_item_code}
              </span>
            )}
            <h4 className="font-medium text-white truncate">{item.title}</h4>
          </div>

          {item.description && (
            <p className="text-sm text-slate-400 line-clamp-2">{item.description}</p>
          )}

          {/* Expand/Collapse for details */}
          {(item.guidance || item.expected_evidence || tools.length > 0 || references.length > 0) && (
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="flex items-center gap-1 mt-2 text-xs text-primary hover:text-primary/80 transition-colors"
            >
              {isExpanded ? (
                <>
                  <ChevronUp className="h-3.5 w-3.5" />
                  Hide Details
                </>
              ) : (
                <>
                  <ChevronDown className="h-3.5 w-3.5" />
                  Show Details
                </>
              )}
            </button>
          )}
        </div>

        {/* Status Selector */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowNotes(!showNotes)}
            className={`p-1.5 rounded transition-colors ${
              item.notes
                ? 'text-primary bg-primary/10'
                : 'text-slate-400 hover:text-white hover:bg-dark-hover'
            }`}
            title={item.notes ? 'View/Edit Notes' : 'Add Notes'}
          >
            <FileText className="h-4 w-4" />
          </button>

          <div className="flex items-center gap-1 bg-dark-hover rounded-lg p-1">
            {(Object.entries(statusConfig) as [ChecklistItemStatus, typeof currentStatus][]).map(
              ([status, config]) => {
                const Icon = config.icon;
                const isActive = item.status === status;
                return (
                  <button
                    key={status}
                    onClick={() => !isUpdating && onStatusChange(status)}
                    disabled={isUpdating}
                    className={`p-1.5 rounded transition-colors ${
                      isActive
                        ? `${config.bg} ${config.color}`
                        : 'text-slate-500 hover:text-slate-300 hover:bg-dark-surface'
                    }`}
                    title={config.label}
                  >
                    <Icon className="h-4 w-4" />
                  </button>
                );
              }
            )}
          </div>
        </div>
      </div>

      {/* Expanded Details */}
      {isExpanded && (
        <div className="mt-4 space-y-4 pl-4 border-l-2 border-dark-border">
          {item.guidance && (
            <div>
              <div className="flex items-center gap-2 text-sm font-medium text-slate-300 mb-1">
                <BookOpen className="h-4 w-4" />
                Guidance
              </div>
              <p className="text-sm text-slate-400 whitespace-pre-wrap">{item.guidance}</p>
            </div>
          )}

          {item.expected_evidence && (
            <div>
              <div className="flex items-center gap-2 text-sm font-medium text-slate-300 mb-1">
                <FileText className="h-4 w-4" />
                Expected Evidence
              </div>
              <p className="text-sm text-slate-400">{item.expected_evidence}</p>
            </div>
          )}

          {tools.length > 0 && (
            <div>
              <div className="flex items-center gap-2 text-sm font-medium text-slate-300 mb-1">
                <Wrench className="h-4 w-4" />
                Suggested Tools
              </div>
              <div className="flex flex-wrap gap-1">
                {tools.map((tool, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 text-xs bg-dark-hover text-slate-300 rounded"
                  >
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          )}

          {references.length > 0 && (
            <div>
              <div className="flex items-center gap-2 text-sm font-medium text-slate-300 mb-1">
                <ExternalLink className="h-4 w-4" />
                References
              </div>
              <div className="space-y-1">
                {references.map((ref, idx) => (
                  <a
                    key={idx}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block text-sm text-primary hover:text-primary/80 truncate"
                  >
                    {ref}
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Notes Section */}
      {showNotes && (
        <div className="mt-4">
          <label className="block text-sm font-medium text-slate-300 mb-1">
            Notes
          </label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            onBlur={handleNotesBlur}
            placeholder="Add notes, findings, or observations..."
            className="w-full px-3 py-2 bg-dark-hover border border-dark-border rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary resize-none"
            rows={3}
          />
        </div>
      )}

      {/* Tested info */}
      {item.tested_at && (
        <div className="mt-2 text-xs text-slate-500">
          Tested: {new Date(item.tested_at).toLocaleString()}
        </div>
      )}
    </div>
  );
};

export default ItemCard;
