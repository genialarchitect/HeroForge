import React from 'react';
import { Check, Loader2 } from 'lucide-react';

interface Phase {
  name: string;
  label: string;
  progressStart: number;
  progressEnd: number;
}

const SCAN_PHASES: Phase[] = [
  { name: 'discovery', label: 'Host Discovery', progressStart: 0, progressEnd: 20 },
  { name: 'port_scan', label: 'Port Scanning', progressStart: 20, progressEnd: 40 },
  { name: 'service_detection', label: 'Service Detection', progressStart: 40, progressEnd: 50 },
  { name: 'enumeration', label: 'Enumeration', progressStart: 50, progressEnd: 70 },
  { name: 'os_fingerprint', label: 'OS Fingerprinting', progressStart: 70, progressEnd: 85 },
  { name: 'vuln_scan', label: 'Vulnerability Scan', progressStart: 85, progressEnd: 100 },
];

interface PhaseProgressBarProps {
  currentPhase?: string;
  progress?: number;
  isComplete?: boolean;
}

const PhaseProgressBar: React.FC<PhaseProgressBarProps> = ({
  currentPhase,
  progress = 0,
  isComplete = false,
}) => {
  const getCurrentPhaseIndex = () => {
    if (isComplete) return SCAN_PHASES.length;
    if (!currentPhase) return -1;

    // Match phase name (case-insensitive, handle variations)
    const normalizedPhase = currentPhase.toLowerCase().replace(/\s+/g, '_');
    return SCAN_PHASES.findIndex(phase =>
      phase.name === normalizedPhase ||
      phase.label.toLowerCase().replace(/\s+/g, '_') === normalizedPhase
    );
  };

  const currentPhaseIndex = getCurrentPhaseIndex();

  const getPhaseStatus = (index: number): 'completed' | 'active' | 'pending' => {
    if (isComplete || index < currentPhaseIndex) return 'completed';
    if (index === currentPhaseIndex) return 'active';
    return 'pending';
  };

  const getPhaseProgress = (phase: Phase, index: number): number => {
    if (isComplete || index < currentPhaseIndex) return 100;
    if (index === currentPhaseIndex) {
      // Calculate progress within the current phase
      const phaseRange = phase.progressEnd - phase.progressStart;
      const relativeProgress = Math.max(0, progress - phase.progressStart);
      return Math.min(100, (relativeProgress / phaseRange) * 100);
    }
    return 0;
  };

  return (
    <div className="space-y-3">
      {/* Progress Bar */}
      <div className="relative h-2 bg-dark-surface rounded-full overflow-hidden">
        <div
          className="absolute top-0 left-0 h-full bg-gradient-to-r from-primary to-primary-light transition-all duration-500 ease-out"
          style={{ width: `${isComplete ? 100 : progress}%` }}
        >
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white to-transparent opacity-20 animate-pulse-slow" />
        </div>
      </div>

      {/* Progress Percentage */}
      <div className="flex items-center justify-between text-sm">
        <span className="text-slate-400">
          {currentPhase ? (
            <>
              <span className="text-primary font-medium">
                {SCAN_PHASES[currentPhaseIndex]?.label || currentPhase}
              </span>
              {' in progress...'}
            </>
          ) : isComplete ? (
            <span className="text-green-500 font-medium">Scan Complete</span>
          ) : (
            <span className="text-slate-500">Waiting to start...</span>
          )}
        </span>
        <span className="text-white font-semibold">{Math.round(progress)}%</span>
      </div>

      {/* Phase Steps */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2 mt-4">
        {SCAN_PHASES.map((phase, index) => {
          const status = getPhaseStatus(index);
          const phaseProgress = getPhaseProgress(phase, index);

          return (
            <div
              key={phase.name}
              className={`relative p-3 rounded-lg border transition-all ${
                status === 'completed'
                  ? 'bg-green-500/10 border-green-500/50'
                  : status === 'active'
                  ? 'bg-primary/20 border-primary animate-pulse-dot'
                  : 'bg-dark-surface border-dark-border'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span
                  className={`text-xs font-medium ${
                    status === 'completed'
                      ? 'text-green-500'
                      : status === 'active'
                      ? 'text-primary'
                      : 'text-slate-500'
                  }`}
                >
                  {phase.label}
                </span>
                {status === 'completed' ? (
                  <Check className="h-4 w-4 text-green-500 flex-shrink-0" />
                ) : status === 'active' ? (
                  <Loader2 className="h-4 w-4 text-primary animate-spin flex-shrink-0" />
                ) : (
                  <div className="h-4 w-4 rounded-full border-2 border-slate-600 flex-shrink-0" />
                )}
              </div>

              {/* Mini progress bar for active phase */}
              {status === 'active' && (
                <div className="h-1 bg-dark-bg rounded-full overflow-hidden mt-2">
                  <div
                    className="h-full bg-primary transition-all duration-300"
                    style={{ width: `${phaseProgress}%` }}
                  />
                </div>
              )}

              {status === 'completed' && (
                <div className="text-xs text-green-500/70 mt-1">✓ Done</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default PhaseProgressBar;
