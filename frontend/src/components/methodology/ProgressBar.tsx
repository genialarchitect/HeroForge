import React from 'react';

interface ProgressBarProps {
  progress: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  className?: string;
}

const ProgressBar: React.FC<ProgressBarProps> = ({
  progress,
  size = 'md',
  showLabel = false,
  className = '',
}) => {
  const clampedProgress = Math.min(100, Math.max(0, progress));

  const getBarHeight = () => {
    switch (size) {
      case 'sm':
        return 'h-1.5';
      case 'lg':
        return 'h-4';
      default:
        return 'h-2.5';
    }
  };

  const getProgressColor = () => {
    if (clampedProgress >= 100) return 'bg-green-500';
    if (clampedProgress >= 75) return 'bg-cyan-500';
    if (clampedProgress >= 50) return 'bg-yellow-500';
    if (clampedProgress >= 25) return 'bg-orange-500';
    return 'bg-red-500';
  };

  return (
    <div className={`w-full ${className}`}>
      {showLabel && (
        <div className="flex justify-between items-center mb-1">
          <span className="text-xs text-slate-400">Progress</span>
          <span className="text-xs font-medium text-white">
            {clampedProgress.toFixed(0)}%
          </span>
        </div>
      )}
      <div className={`w-full bg-dark-hover rounded-full overflow-hidden ${getBarHeight()}`}>
        <div
          className={`${getBarHeight()} ${getProgressColor()} rounded-full transition-all duration-300`}
          style={{ width: `${clampedProgress}%` }}
        />
      </div>
    </div>
  );
};

export default ProgressBar;
