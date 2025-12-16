import React, { useMemo, useState } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import PhaseProgress from './PhaseProgress';
import LiveMetrics from './LiveMetrics';
import { Activity, Wifi, WifiOff, ChevronDown, ChevronUp, Clock } from 'lucide-react';
import { useWebSocket } from '../../hooks/useWebSocket';
import { useScanStore } from '../../store/scanStore';

interface ScanProgressCardProps {
  scanId: string | null;
}

const ScanProgressCard: React.FC<ScanProgressCardProps> = ({ scanId }) => {
  const { status, error, reconnect } = useWebSocket(scanId);
  const { liveUpdates, scans } = useScanStore();
  const [isExpanded, setIsExpanded] = useState(true);

  const activeScan = useMemo(() => {
    return scans.find((s) => s.id === scanId);
  }, [scans, scanId]);

  // Calculate metrics and progress from live updates
  const { currentPhase, progress, isComplete, metrics, currentActivity, estimatedTime } = useMemo(() => {
    if (!scanId) {
      return {
        currentPhase: undefined,
        progress: 0,
        isComplete: false,
        metrics: { hostsFound: 0, portsOpen: 0, servicesDetected: 0, vulnerabilitiesFound: 0, criticalVulns: 0, highVulns: 0, mediumVulns: 0, lowVulns: 0 },
        currentActivity: '',
        estimatedTime: null,
      };
    }

    const events = liveUpdates.get(scanId) || [];
    const isComplete = activeScan?.status === 'completed';

    // Find the most recent phase started event
    const phaseEvents = events.filter((e) => e.type === 'phaseStarted');
    const latestPhase = phaseEvents.length > 0 ? phaseEvents[phaseEvents.length - 1] : null;

    // Find the most recent progress event
    const progressEvents = events.filter((e) => e.type === 'scanProgress');
    const latestProgress = progressEvents.length > 0 ? progressEvents[progressEvents.length - 1] : null;

    // Calculate metrics
    const hostEvents = events.filter((e) => e.type === 'hostDiscovered');
    const portEvents = events.filter((e) => e.type === 'portFound');
    const serviceEvents = events.filter((e) => e.type === 'serviceDetected');
    const vulnEvents = events.filter((e) => e.type === 'vulnerabilityFound');

    const criticalVulns = vulnEvents.filter((e) => e.data?.severity === 'Critical').length;
    const highVulns = vulnEvents.filter((e) => e.data?.severity === 'High').length;
    const mediumVulns = vulnEvents.filter((e) => e.data?.severity === 'Medium').length;
    const lowVulns = vulnEvents.filter((e) => e.data?.severity === 'Low').length;

    // Get current activity from latest progress message
    const currentActivity = latestProgress?.data?.message || latestPhase?.data?.phase || '';

    // Calculate estimated time remaining (simple heuristic)
    let estimatedTime = null;
    if (!isComplete && latestProgress && latestProgress.data?.progress > 0) {
      const currentProgress = latestProgress.data.progress;
      const scanStartEvent = events.find((e) => e.type === 'scanStarted');
      if (scanStartEvent) {
        const startTime = new Date(scanStartEvent.timestamp).getTime();
        const now = Date.now();
        const elapsed = (now - startTime) / 1000; // seconds
        const estimatedTotal = (elapsed / currentProgress) * 100;
        estimatedTime = Math.max(0, estimatedTotal - elapsed);
      }
    }

    return {
      currentPhase: latestPhase?.data?.phase,
      progress: latestProgress?.data?.progress || latestPhase?.data?.progress || 0,
      isComplete,
      metrics: {
        hostsFound: hostEvents.length,
        portsOpen: portEvents.length,
        servicesDetected: serviceEvents.length,
        vulnerabilitiesFound: vulnEvents.length,
        criticalVulns,
        highVulns,
        mediumVulns,
        lowVulns,
      },
      currentActivity,
      estimatedTime,
    };
  }, [scanId, liveUpdates, activeScan]);

  const formatTimeRemaining = (seconds: number | null): string => {
    if (seconds === null) return 'Calculating...';
    if (seconds < 60) return `~${Math.round(seconds)}s remaining`;
    if (seconds < 3600) return `~${Math.round(seconds / 60)}m remaining`;
    return `~${Math.round(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}m remaining`;
  };

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
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h3 className="text-xl font-semibold text-white flex items-center">
              <Activity className="h-5 w-5 mr-2" />
              Real-Time Scan Progress
            </h3>
            <Badge variant="status" type={status === 'connected' ? 'running' : 'pending'}>
              {status === 'connected' && (
                <span className="inline-block w-2 h-2 bg-green-500 rounded-full animate-pulse-dot mr-1"></span>
              )}
              Live
            </Badge>
          </div>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-2 hover:bg-dark-hover rounded-lg transition-colors"
          >
            {isExpanded ? (
              <ChevronUp className="h-5 w-5 text-slate-400" />
            ) : (
              <ChevronDown className="h-5 w-5 text-slate-400" />
            )}
          </button>
        </div>

        {/* Connection Status */}
        <div className={`flex items-center space-x-2 ${getStatusColor()}`}>
          {getStatusIcon()}
          <span className="text-sm">{getStatusText()}</span>
        </div>

        {/* Error Message */}
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

        {/* Expanded Content */}
        {isExpanded && (
          <>
            {/* Current Activity & ETA */}
            {showProgressBar && !isComplete && currentActivity && (
              <div className="bg-dark-surface border border-dark-border rounded-lg p-3 space-y-2">
                <div className="flex items-start gap-2">
                  <Activity className="h-4 w-4 text-primary mt-0.5 animate-pulse" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-slate-300">{currentActivity}</p>
                  </div>
                </div>
                {estimatedTime !== null && (
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <Clock className="h-3 w-3" />
                    <span>{formatTimeRemaining(estimatedTime)}</span>
                  </div>
                )}
              </div>
            )}

            {/* Live Metrics */}
            {showProgressBar && (
              <LiveMetrics
                hostsFound={metrics.hostsFound}
                portsOpen={metrics.portsOpen}
                servicesDetected={metrics.servicesDetected}
                vulnerabilitiesFound={metrics.vulnerabilitiesFound}
                criticalVulns={metrics.criticalVulns}
                highVulns={metrics.highVulns}
                mediumVulns={metrics.mediumVulns}
                lowVulns={metrics.lowVulns}
              />
            )}

            {/* Phase Progress */}
            {showProgressBar && (
              <div className="border-t border-dark-border pt-4">
                <PhaseProgress
                  currentPhase={currentPhase}
                  progress={progress}
                  isComplete={isComplete}
                />
              </div>
            )}

            {/* Waiting State */}
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
          </>
        )}
      </div>
    </Card>
  );
};

export default ScanProgressCard;
