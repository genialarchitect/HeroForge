import React from 'react';
import { ScanResult } from '../../types';
import Badge from '../ui/Badge';
import { Clock, Target } from 'lucide-react';
import { format } from 'date-fns';

interface ScanCardProps {
  scan: ScanResult;
  isActive: boolean;
  onClick: () => void;
}

const ScanCard: React.FC<ScanCardProps> = ({ scan, isActive, onClick }) => {
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
