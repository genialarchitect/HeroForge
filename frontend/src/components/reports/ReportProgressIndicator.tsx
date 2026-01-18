import React from 'react';
import {
  RefreshCw,
  CheckCircle,
  XCircle,
  FileText,
  Camera,
  Loader2,
  AlertCircle,
} from 'lucide-react';
import { useReportWebSocket } from '../../hooks/useReportWebSocket';

interface ReportProgressIndicatorProps {
  reportId: string;
  onComplete?: () => void;
  onError?: (error: string) => void;
}

const PHASE_ICONS: Record<string, React.ReactNode> = {
  started: <FileText className="w-4 h-4" />,
  loading: <Loader2 className="w-4 h-4 animate-spin" />,
  preparing: <RefreshCw className="w-4 h-4 animate-spin" />,
  screenshots: <Camera className="w-4 h-4" />,
  rendering: <RefreshCw className="w-4 h-4 animate-spin" />,
  completed: <CheckCircle className="w-4 h-4 text-green-400" />,
  failed: <XCircle className="w-4 h-4 text-red-400" />,
};

const PHASE_LABELS: Record<string, string> = {
  started: 'Starting',
  loading: 'Loading Data',
  preparing: 'Preparing Report',
  screenshots: 'Capturing Screenshots',
  rendering: 'Rendering Report',
  completed: 'Completed',
  failed: 'Failed',
};

export default function ReportProgressIndicator({
  reportId,
  onComplete,
  onError,
}: ReportProgressIndicatorProps) {
  const { status, progress, error } = useReportWebSocket(reportId);

  // Call onComplete when status becomes 'completed'
  React.useEffect(() => {
    if (status === 'completed' && onComplete) {
      onComplete();
    }
  }, [status, onComplete]);

  // Call onError when status becomes 'failed' or there's an error
  React.useEffect(() => {
    if ((status === 'failed' || error) && onError) {
      onError(error || 'Report generation failed');
    }
  }, [status, error, onError]);

  if (!progress && status === 'connecting') {
    return (
      <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
        <div className="flex items-center gap-3">
          <RefreshCw className="w-5 h-5 text-cyan-400 animate-spin" />
          <div className="flex-1">
            <p className="text-sm text-white">Connecting to report progress...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!progress) {
    return null;
  }

  const phase = progress.phase || 'loading';
  const phaseIcon = PHASE_ICONS[phase] || <Loader2 className="w-4 h-4 animate-spin" />;
  const phaseLabel = PHASE_LABELS[phase] || phase;
  const progressPercent = Math.round((progress.progress || 0) * 100);

  return (
    <div
      className={`rounded-lg p-4 border ${
        status === 'failed'
          ? 'bg-red-500/10 border-red-500/30'
          : status === 'completed'
          ? 'bg-green-500/10 border-green-500/30'
          : 'bg-slate-700/50 border-slate-600'
      }`}
    >
      <div className="flex items-center gap-3 mb-3">
        <div
          className={`p-2 rounded-lg ${
            status === 'failed'
              ? 'bg-red-500/20'
              : status === 'completed'
              ? 'bg-green-500/20'
              : 'bg-cyan-500/20'
          }`}
        >
          {phaseIcon}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-white">{phaseLabel}</p>
            <span className="text-xs text-slate-400">{progressPercent}%</span>
          </div>
          <p className="text-xs text-slate-400 truncate">{progress.message}</p>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="h-2 bg-slate-600 rounded-full overflow-hidden">
        <div
          className={`h-full transition-all duration-300 ease-out ${
            status === 'failed'
              ? 'bg-red-500'
              : status === 'completed'
              ? 'bg-green-500'
              : 'bg-cyan-500'
          }`}
          style={{ width: `${progressPercent}%` }}
        />
      </div>

      {/* Screenshot Progress */}
      {phase === 'screenshots' &&
        progress.screenshotIndex !== undefined &&
        progress.screenshotTotal !== undefined && (
          <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
            <Camera className="w-3 h-3" />
            <span>
              Screenshot {(progress.screenshotIndex || 0) + 1} of{' '}
              {progress.screenshotTotal}
            </span>
          </div>
        )}

      {/* Error Message */}
      {error && (
        <div className="mt-3 flex items-start gap-2 p-2 bg-red-500/10 rounded border border-red-500/20">
          <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-red-300">{error}</p>
        </div>
      )}
    </div>
  );
}

/**
 * Inline progress indicator for use in report list rows
 */
export function ReportProgressInline({
  reportId,
}: {
  reportId: string;
}) {
  const { status, progress } = useReportWebSocket(reportId);

  if (status === 'completed' || status === 'failed') {
    return null;
  }

  const progressPercent = Math.round((progress?.progress || 0) * 100);

  return (
    <div className="flex items-center gap-2">
      <div className="w-24 h-1.5 bg-slate-600 rounded-full overflow-hidden">
        <div
          className="h-full bg-cyan-500 transition-all duration-300 ease-out"
          style={{ width: `${progressPercent}%` }}
        />
      </div>
      <span className="text-xs text-slate-400">{progressPercent}%</span>
    </div>
  );
}
