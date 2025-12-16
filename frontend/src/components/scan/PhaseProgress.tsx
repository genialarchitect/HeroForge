import React from 'react';
import { Check, Loader2, Circle } from 'lucide-react';

interface Phase {
  name: string;
  label: string;
  progressStart: number;
  progressEnd: number;
}

const SCAN_PHASES: Phase[] = [
  { name: 'host_discovery', label: 'Host Discovery', progressStart: 0, progressEnd: 20 },
  { name: 'port_scanning', label: 'Port Scanning', progressStart: 20, progressEnd: 40 },
  { name: 'service_detection', label: 'Service Detection', progressStart: 40, progressEnd: 60 },
  { name: 'enumeration', label: 'Enumeration', progressStart: 60, progressEnd: 75 },
  { name: 'os_fingerprinting', label: 'OS Fingerprinting', progressStart: 75, progressEnd: 85 },
  { name: 'vulnerability_scanning', label: 'Vulnerability Scanning', progressStart: 85, progressEnd: 100 },
];

interface PhaseProgressProps {
  currentPhase?: string;
  progress?: number;
  isComplete?: boolean;
}

const PhaseProgress: React.FC<PhaseProgressProps> = ({
  currentPhase,
  progress = 0,
  isComplete = false,
}) => {
  const normalizePhase = (phase: string): string => {
    return phase.toLowerCase().replace(/\s+/g, '_');
  };

  const getCurrentPhaseIndex = (): number => {
    if (isComplete) return SCAN_PHASES.length;
    if (!currentPhase) return -1;

    const normalized = normalizePhase(currentPhase);
    return SCAN_PHASES.findIndex(
      (phase) =>
        phase.name === normalized ||
        normalizePhase(phase.label) === normalized
    );
  };

  const currentPhaseIndex = getCurrentPhaseIndex();

  const getPhaseStatus = (index: number): 'completed' | 'active' | 'pending' => {
    if (isComplete) return 'completed';
    if (index < currentPhaseIndex) return 'completed';
    if (index === currentPhaseIndex) return 'active';
    return 'pending';
  };

  return (
    <div className="space-y-4">
      {/* Phase Timeline */}
      <div className="relative">
        {/* Connection Line */}
        <div className="absolute top-6 left-0 right-0 h-0.5 bg-dark-border" />
        <div
          className="absolute top-6 left-0 h-0.5 bg-gradient-to-r from-primary to-primary-light transition-all duration-500"
          style={{ width: `${isComplete ? 100 : (currentPhaseIndex / SCAN_PHASES.length) * 100}%` }}
        />

        {/* Phase Items */}
        <div className="relative grid grid-cols-6 gap-2">
          {SCAN_PHASES.map((phase, index) => {
            const status = getPhaseStatus(index);

            return (
              <div key={phase.name} className="flex flex-col items-center">
                {/* Icon */}
                <div
                  className={`
                    relative z-10 flex items-center justify-center w-12 h-12 rounded-full border-2 transition-all duration-300
                    ${
                      status === 'completed'
                        ? 'bg-green-500 border-green-500 shadow-lg shadow-green-500/50'
                        : status === 'active'
                        ? 'bg-primary border-primary shadow-lg shadow-primary/50 animate-pulse-glow'
                        : 'bg-dark-surface border-dark-border'
                    }
                  `}
                >
                  {status === 'completed' ? (
                    <Check className="h-6 w-6 text-white" />
                  ) : status === 'active' ? (
                    <Loader2 className="h-6 w-6 text-white animate-spin" />
                  ) : (
                    <Circle className="h-6 w-6 text-slate-600" />
                  )}
                </div>

                {/* Label */}
                <div className="mt-3 text-center">
                  <p
                    className={`text-xs font-medium transition-colors ${
                      status === 'completed'
                        ? 'text-green-500'
                        : status === 'active'
                        ? 'text-primary'
                        : 'text-slate-500'
                    }`}
                  >
                    {phase.label}
                  </p>
                  {status === 'active' && (
                    <p className="text-xs text-slate-400 mt-1">In Progress...</p>
                  )}
                  {status === 'completed' && (
                    <p className="text-xs text-green-500/70 mt-1">Complete</p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Overall Progress Bar */}
      <div className="space-y-2 pt-4 border-t border-dark-border">
        <div className="flex items-center justify-between text-sm">
          <span className="text-slate-400">
            {isComplete ? (
              <span className="text-green-500 font-medium">Scan Complete</span>
            ) : currentPhase ? (
              <>
                <span className="text-primary font-medium">
                  {SCAN_PHASES[currentPhaseIndex]?.label || currentPhase}
                </span>
                {' in progress...'}
              </>
            ) : (
              <span className="text-slate-500">Initializing...</span>
            )}
          </span>
          <span className="text-white font-semibold tabular-nums">{Math.round(progress)}%</span>
        </div>

        <div className="relative h-3 bg-dark-surface rounded-full overflow-hidden">
          <div
            className="absolute top-0 left-0 h-full bg-gradient-to-r from-primary via-primary-light to-primary transition-all duration-500 ease-out"
            style={{ width: `${isComplete ? 100 : progress}%` }}
          >
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white to-transparent opacity-30 animate-shimmer" />
          </div>
        </div>
      </div>
    </div>
  );
};

export default PhaseProgress;
