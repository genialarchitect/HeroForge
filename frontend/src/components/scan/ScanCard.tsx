import React from 'react';
import { ScanResult, ScanTag } from '../../types';
import Badge from '../ui/Badge';
import { Clock, Target, Tag } from 'lucide-react';
import { format } from 'date-fns';

interface ScanCardProps {
  scan: ScanResult;
  isActive: boolean;
  onClick: () => void;
  tags?: ScanTag[];
  onTagClick?: (tagId: string) => void;
}

const ScanCard: React.FC<ScanCardProps> = ({ scan, isActive, onClick, tags, onTagClick }) => {
  const targets = JSON.parse(scan.targets);
  const statusType = scan.status as 'pending' | 'running' | 'completed' | 'failed';

  const getStatusDisplay = () => {
    const statusMap = {
      pending: 'Pending',
      running: 'Running',
      completed: 'Completed',
      failed: 'Failed',
    };
    return statusMap[scan.status as keyof typeof statusMap] || scan.status;
  };

  return (
    <div
      onClick={onClick}
      className={`
        p-4 border rounded-lg cursor-pointer transition-all duration-200
        ${isActive
          ? 'bg-primary/10 border-primary shadow-lg'
          : 'bg-dark-surface border-dark-border hover:border-primary/50 hover:shadow-md'
        }
      `}
    >
      <div className="flex items-start justify-between mb-2">
        <h4 className="text-white font-semibold truncate flex-1">{scan.name}</h4>
        <Badge variant="status" type={statusType}>
          {statusType === 'running' && (
            <span className="inline-block w-2 h-2 bg-primary rounded-full animate-pulse-dot mr-1"></span>
          )}
          {getStatusDisplay()}
        </Badge>
      </div>

      {/* Tags display */}
      {tags && tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {tags.slice(0, 3).map((tag) => (
            <button
              key={tag.id}
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onTagClick?.(tag.id);
              }}
              className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium hover:opacity-80 transition-opacity"
              style={{ backgroundColor: tag.color + '20', color: tag.color }}
              title={`Filter by ${tag.name}`}
            >
              <Tag className="h-3 w-3 mr-1" />
              {tag.name}
            </button>
          ))}
          {tags.length > 3 && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs text-slate-400">
              +{tags.length - 3} more
            </span>
          )}
        </div>
      )}

      <div className="space-y-1 text-sm">
        <div className="flex items-center text-slate-400">
          <Target className="h-4 w-4 mr-2" />
          <span className="font-mono text-xs">{targets[0]}</span>
        </div>
        <div className="flex items-center text-slate-500">
          <Clock className="h-4 w-4 mr-2" />
          <span>{format(new Date(scan.created_at), 'MMM d, yyyy HH:mm')}</span>
        </div>
      </div>
    </div>
  );
};

export default ScanCard;
