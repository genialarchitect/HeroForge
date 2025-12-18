import React, { useEffect, useRef, useState } from 'react';
import { Server, Wifi, WifiOff, Code, AlertTriangle, Shield, Activity, Filter, Globe } from 'lucide-react';
import { useScanStore } from '../../store/scanStore';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import { format } from 'date-fns';

interface ActivityFeedProps {
  scanId: string | null;
  maxItems?: number;
}

const ActivityFeed: React.FC<ActivityFeedProps> = ({ scanId, maxItems = 50 }) => {
  const { liveUpdates } = useScanStore();
  const [showCriticalOnly, setShowCriticalOnly] = useState(false);
  const feedEndRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  const events = scanId ? liveUpdates.get(scanId) || [] : [];

  // Filter events if critical-only mode is enabled
  const filteredEvents = showCriticalOnly
    ? events.filter(
        (event) =>
          event.type === 'vulnerabilityFound' &&
          (event.data?.severity === 'Critical' || event.data?.severity === 'High')
      )
    : events;

  // Take only the last N events
  const displayEvents = filteredEvents.slice(-maxItems);

  // Auto-scroll to bottom when new events arrive
  useEffect(() => {
    if (autoScroll && feedEndRef.current) {
      feedEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [displayEvents.length, autoScroll]);

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'hostDiscovered':
        return <Server className="h-4 w-4 text-blue-400" />;
      case 'portFound':
        return <Wifi className="h-4 w-4 text-green-400" />;
      case 'serviceDetected':
        return <Code className="h-4 w-4 text-purple-400" />;
      case 'vulnerabilityFound':
        return <AlertTriangle className="h-4 w-4 text-red-400" />;
      case 'phaseStarted':
        return <Activity className="h-4 w-4 text-primary" />;
      case 'scanStarted':
      case 'scanCompleted':
        return <Shield className="h-4 w-4 text-green-400" />;
      case 'vpnConnecting':
        return <Globe className="h-4 w-4 text-yellow-400 animate-pulse" />;
      case 'vpnConnected':
        return <Globe className="h-4 w-4 text-green-400" />;
      case 'vpnDisconnecting':
        return <WifiOff className="h-4 w-4 text-yellow-400" />;
      case 'vpnDisconnected':
        return <WifiOff className="h-4 w-4 text-slate-400" />;
      case 'vpnError':
        return <Globe className="h-4 w-4 text-red-400" />;
      default:
        return <Activity className="h-4 w-4 text-slate-400" />;
    }
  };

  const getEventMessage = (event: any) => {
    switch (event.type) {
      case 'hostDiscovered':
        return (
          <>
            Discovered host <code className="text-primary font-mono">{event.data?.ip}</code>
            {event.data?.hostname && ` (${event.data.hostname})`}
          </>
        );
      case 'portFound':
        return (
          <>
            Found open port{' '}
            <code className="text-green-400 font-mono">
              {event.data?.port}/{event.data?.protocol}
            </code>{' '}
            on <code className="text-primary font-mono">{event.data?.ip}</code>
          </>
        );
      case 'serviceDetected':
        return (
          <>
            Detected service <code className="text-purple-400">{event.data?.service_name}</code> on{' '}
            <code className="text-primary font-mono">{event.data?.ip}</code>:
            {event.data?.port}
          </>
        );
      case 'vulnerabilityFound':
        return (
          <>
            Found{' '}
            <Badge variant="severity" type={event.data?.severity?.toLowerCase() || 'low'}>
              {event.data?.severity}
            </Badge>{' '}
            vulnerability on <code className="text-primary font-mono">{event.data?.ip}</code>:{' '}
            <span className="text-white">{event.data?.title}</span>
          </>
        );
      case 'phaseStarted':
        return (
          <>
            Started phase: <span className="text-primary font-medium">{event.data?.phase}</span>
          </>
        );
      case 'scanStarted':
        return <span className="text-green-400 font-medium">Scan started</span>;
      case 'scanCompleted':
        return (
          <>
            <span className="text-green-400 font-medium">Scan completed</span> - Found{' '}
            {event.data?.total_hosts || 0} hosts in {event.data?.duration || 0}s
          </>
        );
      case 'error':
        return <span className="text-red-400">Error: {event.data?.message}</span>;
      case 'vpnConnecting':
        return (
          <>
            <span className="text-yellow-400">Connecting to VPN:</span>{' '}
            <span className="text-white">{event.data?.config_name}</span>
          </>
        );
      case 'vpnConnected':
        return (
          <>
            <span className="text-green-400 font-medium">VPN connected</span> - {event.data?.config_name}
            {event.data?.assigned_ip && (
              <> (IP: <code className="text-primary font-mono">{event.data.assigned_ip}</code>)</>
            )}
          </>
        );
      case 'vpnDisconnecting':
        return (
          <>
            <span className="text-yellow-400">Disconnecting from VPN:</span>{' '}
            <span className="text-white">{event.data?.config_name}</span>
          </>
        );
      case 'vpnDisconnected':
        return (
          <>
            <span className="text-slate-400">VPN disconnected:</span>{' '}
            <span className="text-white">{event.data?.config_name}</span>
          </>
        );
      case 'vpnError':
        return (
          <>
            <span className="text-red-400">VPN Error ({event.data?.config_name}):</span>{' '}
            {event.data?.message}
          </>
        );
      default:
        return <span className="text-slate-400">{event.type}</span>;
    }
  };

  const getEventColor = (event: any) => {
    if (event.type === 'vulnerabilityFound') {
      switch (event.data?.severity) {
        case 'Critical':
          return 'border-l-severity-critical bg-severity-critical/5';
        case 'High':
          return 'border-l-severity-high bg-severity-high/5';
        case 'Medium':
          return 'border-l-severity-medium bg-severity-medium/5';
        default:
          return 'border-l-severity-low bg-severity-low/5';
      }
    }
    if (event.type === 'vpnConnecting' || event.type === 'vpnDisconnecting') {
      return 'border-l-yellow-500 bg-yellow-500/5';
    }
    if (event.type === 'vpnConnected') {
      return 'border-l-green-500 bg-green-500/5';
    }
    if (event.type === 'vpnError') {
      return 'border-l-red-500 bg-red-500/5';
    }
    return 'border-l-slate-600 bg-dark-bg';
  };

  if (!scanId) {
    return (
      <Card>
        <div className="text-center py-8 text-slate-500">
          Select a running scan to view live activity
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-primary" />
          <h3 className="text-lg font-semibold text-white">Live Activity Feed</h3>
          <span className="text-sm text-slate-400">({displayEvents.length} events)</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowCriticalOnly(!showCriticalOnly)}
            className={`flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm transition-colors ${
              showCriticalOnly
                ? 'bg-red-500/20 text-red-400 border border-red-500/50'
                : 'bg-dark-surface text-slate-400 border border-dark-border hover:border-primary'
            }`}
          >
            <Filter className="h-3 w-3" />
            {showCriticalOnly ? 'Critical/High Only' : 'All Events'}
          </button>
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
              autoScroll
                ? 'bg-primary text-white'
                : 'bg-dark-surface text-slate-400 border border-dark-border'
            }`}
          >
            Auto-scroll
          </button>
        </div>
      </div>

      <div className="space-y-2 max-h-96 overflow-y-auto pr-2 custom-scrollbar">
        {displayEvents.length === 0 ? (
          <div className="text-center py-8 text-slate-500">
            {showCriticalOnly
              ? 'No critical/high severity findings yet'
              : 'Waiting for scan events...'}
          </div>
        ) : (
          displayEvents.map((event, index) => (
            <div
              key={index}
              className={`border-l-4 rounded-r-lg p-3 transition-all hover:bg-dark-surface/50 ${getEventColor(
                event
              )}`}
            >
              <div className="flex items-start gap-3">
                <div className="mt-0.5">{getEventIcon(event.type)}</div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-slate-300">{getEventMessage(event)}</p>
                  <p className="text-xs text-slate-500 mt-1">
                    {format(new Date(event.timestamp), 'HH:mm:ss.SSS')}
                  </p>
                </div>
              </div>
            </div>
          ))
        )}
        <div ref={feedEndRef} />
      </div>
    </Card>
  );
};

export default ActivityFeed;
