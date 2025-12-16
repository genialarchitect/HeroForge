import React from 'react';
import { GripVertical, X } from 'lucide-react';

interface WidgetContainerProps {
  title: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
  onRemove?: () => void;
  className?: string;
}

const WidgetContainer: React.FC<WidgetContainerProps> = ({
  title,
  icon,
  children,
  onRemove,
  className = '',
}) => {
  return (
    <div className={`bg-dark-surface border border-dark-border rounded-lg shadow-lg h-full flex flex-col ${className}`}>
      <div className="flex items-center justify-between p-4 border-b border-dark-border">
        <div className="flex items-center gap-2">
          <GripVertical className="h-4 w-4 text-slate-400 cursor-move drag-handle" />
          {icon && <div className="text-primary">{icon}</div>}
          <h3 className="text-lg font-semibold text-white">{title}</h3>
        </div>
        {onRemove && (
          <button
            onClick={onRemove}
            className="p-1 text-slate-400 hover:text-white hover:bg-dark-hover rounded transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
      <div className="flex-1 p-4 overflow-auto">
        {children}
      </div>
    </div>
  );
};

export default WidgetContainer;
