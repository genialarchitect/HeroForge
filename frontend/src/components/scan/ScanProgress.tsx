import React, { useMemo } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import { Activity, Wifi, WifiOff } from 'lucide-react';
import { useWebSocket } from '../../hooks/useWebSocket';
import { useScanStore } from '../../store/scanStore';
import PhaseProgressBar from './PhaseProgressBar';

interface ScanProgressProps {
  scanId: string | null;
}

const ScanProgress: React.FC<ScanProgressProps> = ({ scanId }) => {
  const { status, error, reconnect } = useWebSocket(scanId);
  const { liveUpdates, scans } = useScanStore();

  const activeScan = useMemo(() => {
    return scans.find((s) => s.id === scanId);
  }, [scans, scanId]);

  // Extract current phase and progress from live updates
  const { currentPhase, progress, isComplete } = useMemo(() => {
    if (!scanId) return { currentPhase: undefined, progress: 0, isComplete: false };

    const events = liveUpdates.get(scanId) || [];
    const isComplete = activeScan?.status === 'completed';

    // Find the most recent phase started event
    const phaseEvents = events.filter((e) => e.type === 'phaseStarted');
    const latestPhase = phaseEvents.length > 0 ? phaseEvents[phaseEvents.length - 1] : null;

    // Find the most recent progress event
    const progressEvents = events.filter((e) => e.type === 'scanProgress');
    const latestProgress = progressEvents.length > 0 ? progressEvents[progressEvents.length - 1] : null;

    return {
      currentPhase: latestPhase?.data?.phase,
      progress: latestProgress?.data?.progress || (latestPhase?.data?.progress) || 0,
      isComplete,
    };
  }, [scanId, liveUpdates, activeScan]);

  if (!scanId) {
    return (
      <Card>
        <div className="text-center py-8 text-slate-500">
          Select a scan to view real-time progress
        </div>
      </Card>
    );
  }

  const getStatusColor = () => {
    switch (status) {
      case 'connected':
        return 'text-green-500';
      case 'connecting':
        return 'text-yellow-500';
      case 'disconnected':
      case 'failed':
        return 'text-red-500';
      default:
        return 'text-slate-500';
    }
  };

  const getStatusIcon = () => {
    if (status === 'connected') {
      return <Wifi className="h-5 w-5" />;
    }
    return <WifiOff className="h-5 w-5" />;
  };

  const getStatusText = () => {
    switch (status) {
      case 'connected':
        return 'Connected - Receiving live updates';
      case 'connecting':
        return 'Connecting to scan...';
      case 'disconnected':
        return 'Disconnected';
      case 'failed':
        return 'Connection failed';
      default:
        return 'Unknown';
    }
  };

  const showProgressBar = activeScan?.status === 'running' || activeScan?.status === 'completed';

  return (
    <Card>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xl font-semibold text-white flex items-center">
            <Activity className="h-5 w-5 mr-2" />
            Real-Time Progress
          </h3>
          <Badge variant="status" type={status === 'connected' ? 'running' : 'pending'}>
            {status === 'connected' && (
              <span className="inline-block w-2 h-2 bg-green-500 rounded-full animate-pulse-dot mr-1"></span>
            )}
            Live
          </Badge>
        </div>

        <div className={`flex items-center space-x-2 ${getStatusColor()}`}>
          {getStatusIcon()}
          <span className="text-sm">{getStatusText()}</span>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
            <p className="text-red-500 text-sm">{error}</p>
            <button
              onClick={reconnect}
              className="mt-2 text-xs text-red-400 hover:text-red-300 underline"
            >
              Try reconnecting
            </button>
          </div>
        )}

        {/* Phase Progress Bar */}
        {showProgressBar && (
          <div className="border-t border-dark-border pt-4">
            <PhaseProgressBar
              currentPhase={currentPhase}
              progress={progress}
              isComplete={isComplete}
            />
          </div>
        )}

        {status === 'connected' && !showProgressBar && (
          <div className="border-t border-dark-border pt-4 text-sm text-slate-400">
            <p>Listening for scan events:</p>
            <ul className="mt-2 space-y-1 text-xs">
              <li>• Host discoveries</li>
              <li>• Open ports</li>
              <li>• Service detections</li>
              <li>• Vulnerability findings</li>
            </ul>
          </div>
        )}
      </div>
    </Card>
  );
};

export default ScanProgress;
