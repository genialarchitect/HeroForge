import React from 'react';
import type { ComplianceFramework } from '../../types';
import Badge from '../ui/Badge';
import Checkbox from '../ui/Checkbox';
import { Shield, CheckCircle2 } from 'lucide-react';

interface FrameworkCardProps {
  framework: ComplianceFramework;
  isSelected: boolean;
  onToggle: () => void;
}

const FrameworkCard: React.FC<FrameworkCardProps> = ({
  framework,
  isSelected,
  onToggle,
}) => {
  return (
    <div
      onClick={onToggle}
      className={`p-4 rounded-lg border cursor-pointer transition-all hover:shadow-lg ${
        isSelected
          ? 'border-primary bg-primary/10 shadow-primary/20'
          : 'border-dark-border bg-dark-surface hover:border-primary/50'
      }`}
    >
      <div className="flex items-start gap-3">
        <Checkbox checked={isSelected} onChange={onToggle} />
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2 mb-2">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary flex-shrink-0" />
              <h3 className="font-semibold text-white truncate">{framework.name}</h3>
            </div>
            <Badge variant="status" type="running">
              v{framework.version}
            </Badge>
          </div>

          <p className="text-sm text-slate-400 mb-3 line-clamp-2">
            {framework.description}
          </p>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4 text-xs">
              <div className="flex items-center gap-1 text-slate-500">
                <Shield className="h-3.5 w-3.5" />
                <span>{framework.control_count} controls</span>
              </div>
              <div className="flex items-center gap-1 text-green-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                <span>{framework.automated_percentage.toFixed(0)}% automated</span>
              </div>
            </div>
          </div>

          {/* Progress bar for automation */}
          <div className="mt-3 w-full bg-dark-border rounded-full h-1.5">
            <div
              className="bg-gradient-to-r from-green-500 to-primary h-1.5 rounded-full transition-all"
              style={{ width: `${framework.automated_percentage}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default FrameworkCard;
