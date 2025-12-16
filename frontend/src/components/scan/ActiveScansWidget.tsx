import React, { useMemo } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import { Activity, ChevronRight, Loader2, CheckCircle, XCircle } from 'lucide-react';
import { useScanStore } from '../../store/scanStore';
import { ScanResult } from '../../types';

interface ActiveScansWidgetProps {
  onScanSelect?: (scanId: string) => void;
}

const ActiveScansWidget: React.FC<ActiveScansWidgetProps> = ({ onScanSelect }) => {
  const { scans, liveUpdates, activeScan } = useScanStore();

  // Filter for running scans
  const runningScans = useMemo(() => {
    return scans.filter((scan) => scan.status === 'running');
  }, [scans]);

  // Calculate progress for each running scan
  const scanProgress = useMemo(() => {
    const progressMap = new Map<string, number>();

    runningScans.forEach((scan) => {
      const events = liveUpdates.get(scan.id) || [];
      const progressEvents = events.filter((e) => e.type === 'scanProgress' || e.type === 'phaseStarted');
      const latestProgress = progressEvents.length > 0 ? progressEvents[progressEvents.length - 1] : null;
      progressMap.set(scan.id, latestProgress?.data?.progress || 0);
    });

    return progressMap;
  }, [runningScans, liveUpdates]);

  // Calculate aggregate stats
  const aggregateStats = useMemo(() => {
    let totalProgress = 0;
    let totalHosts = 0;
    let totalVulns = 0;

    runningScans.forEach((scan) => {
      const events = liveUpdates.get(scan.id) || [];
      totalProgress += scanProgress.get(scan.id) || 0;
      totalHosts += events.filter((e) => e.type === 'hostDiscovered').length;
      totalVulns += events.filter((e) => e.type === 'vulnerabilityFound').length;
    });

    const avgProgress = runningScans.length > 0 ? totalProgress / runningScans.length : 0;

    return {
      totalScans: runningScans.length,
      avgProgress,
      totalHosts,
      totalVulns,
    };
  }, [runningScans, liveUpdates, scanProgress]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <Loader2 className="h-4 w-4 text-primary animate-spin" />;
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return <Activity className="h-4 w-4 text-slate-400" />;
    }
  };

  const formatDuration = (scan: ScanResult): string => {
    if (!scan.started_at) return '';

    const start = new Date(scan.started_at).getTime();
    const end = scan.completed_at ? new Date(scan.completed_at).getTime() : Date.now();
    const durationSeconds = Math.floor((end - start) / 1000);

    if (durationSeconds < 60) return `${durationSeconds}s`;
    if (durationSeconds < 3600) return `${Math.floor(durationSeconds / 60)}m`;
    return `${Math.floor(durationSeconds / 3600)}h ${Math.floor((durationSeconds % 3600) / 60)}m`;
  };

  if (runningScans.length === 0) {
    return null; // Don't show widget if no active scans
  }

  return (
    <Card>
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-primary" />
            <h3 className="text-lg font-semibold text-white">Active Scans</h3>
            <Badge variant="status" type="running">
              {aggregateStats.totalScans} Running
            </Badge>
          </div>
        </div>

        {/* Aggregate Stats */}
        <div className="grid grid-cols-3 gap-3 pb-3 border-b border-dark-border">
          <div className="text-center">
            <p className="text-2xl font-bold text-primary">{Math.round(aggregateStats.avgProgress)}%</p>
            <p className="text-xs text-slate-400">Avg Progress</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-blue-400">{aggregateStats.totalHosts}</p>
            <p className="text-xs text-slate-400">Total Hosts</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-red-400">{aggregateStats.totalVulns}</p>
            <p className="text-xs text-slate-400">Total Vulns</p>
          </div>
        </div>

        {/* Scan List */}
        <div className="space-y-2 max-h-80 overflow-y-auto custom-scrollbar">
          {runningScans.map((scan) => {
            const progress = scanProgress.get(scan.id) || 0;
            const isActive = activeScan?.id === scan.id;

            return (
              <div
                key={scan.id}
                onClick={() => onScanSelect?.(scan.id)}
                className={`
                  group relative p-3 rounded-lg border transition-all cursor-pointer
                  ${isActive
                    ? 'bg-primary/10 border-primary'
                    : 'bg-dark-surface border-dark-border hover:border-primary/50 hover:bg-dark-hover'
                  }
                `}
              >
                {/* Progress Background */}
                <div
                  className="absolute inset-0 bg-primary/5 rounded-lg transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />

                {/* Content */}
                <div className="relative flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    {getStatusIcon(scan.status)}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-white truncate">{scan.name}</p>
                      <p className="text-xs text-slate-400 truncate">{scan.targets}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    {/* Progress */}
                    <div className="text-right">
                      <p className="text-sm font-semibold text-primary tabular-nums">{Math.round(progress)}%</p>
                      <p className="text-xs text-slate-500">{formatDuration(scan)}</p>
                    </div>

                    {/* Arrow */}
                    <ChevronRight className={`h-4 w-4 text-slate-400 transition-transform ${isActive ? 'text-primary' : 'group-hover:translate-x-1'}`} />
                  </div>
                </div>

                {/* Mini Progress Bar */}
                <div className="relative mt-2 h-1 bg-dark-bg rounded-full overflow-hidden">
                  <div
                    className="absolute top-0 left-0 h-full bg-gradient-to-r from-primary to-primary-light transition-all duration-500"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </Card>
  );
};

export default ActiveScansWidget;
